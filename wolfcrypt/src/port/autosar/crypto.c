/* crypto.c
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

#ifdef WOLFSSL_AUTOSAR
#ifndef NO_WOLFSSL_AUTOSAR_CRYPTO

#include <wolfssl/wolfcrypt/port/autosar/Csm.h>
#include <wolfssl/wolfcrypt/port/autosar/Crypto.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/random.h>
#ifdef WOLFSSL_AUTOSAR_CMAC
    #include <wolfssl/wolfcrypt/cmac.h>
#endif

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/* Low level crypto (software based driver) where wolfCrypt gets called */
Std_ReturnType wolfSSL_Crypto_CBC(Crypto_JobType* job);
Std_ReturnType wolfSSL_Crypto(Crypto_JobType* job);
Std_ReturnType wolfSSL_Crypto_RNG(Crypto_JobType* job);
#ifdef WOLFSSL_AUTOSAR_CMAC
Std_ReturnType wolfSSL_Crypto_CMAC(Crypto_JobType* job);
#endif


/* Key input redirection and the MAC services cannot both be configured.
 *
 * Redirection maps a key element ID to ONE keystore slot for every service,
 * and the specification scopes element IDs per key, so CRYPTO_KE_CIPHER_KEY
 * and CRYPTO_KE_MAC_KEY are both 0x01. A redirected build therefore resolves
 * cipher and MAC jobs to the same slot: whichever key is in it, the other
 * service runs under the wrong one and reports success. The scan path can at
 * least notice more than one candidate and refuse; here there is always
 * exactly one, so nothing can tell them apart.
 *
 * Refused at build time rather than per job, because refusing per job would
 * mean no unnamed job could ever resolve element 0x01 in such a build -- the
 * standard Csm_Encrypt()/Csm_MacGenerate() entry points would stop working
 * and only the wolfSSL *WithKey() extensions would be usable, which is not
 * something an AUTOSAR port should quietly become.
 *
 * The ways forward, in the order worth trying:
 *   - Drop REDIRECTION_CONFIG and name the slot per job with
 *     wolfSSL_Csm_EncryptWithKey() / wolfSSL_Csm_MacGenerateWithKey(). That
 *     is unambiguous and needs no build-time key map.
 *   - Keep redirection and build without --enable-autosar-cmac, if the ECU
 *     does not need the MAC services.
 *   - Define WOLFSSL_AUTOSAR_ALLOW_AMBIGUOUS_KEY_ELEMENT to accept that the
 *     redirected slot serves both, which is safe only where one of the two
 *     services is never used.
 */
#if defined(REDIRECTION_CONFIG) && defined(WOLFSSL_AUTOSAR_CMAC) && \
        !defined(WOLFSSL_AUTOSAR_ALLOW_AMBIGUOUS_KEY_ELEMENT)
    #error "REDIRECTION_CONFIG with WOLFSSL_AUTOSAR_CMAC cannot tell a cipher key from a MAC key; see the comment above this #error"
#endif

#ifndef MAX_KEYSTORE
    #define MAX_KEYSTORE 15
#endif
#ifndef MAX_JOBS
    #define MAX_JOBS 10
#endif

/* Heap hint and crypto callback device ID for every wolfCrypt context this
 * driver creates, taken from Crypto_Init()'s config. Set once at init and read
 * without a lock: Crypto_Init() runs before any job can be submitted. */
static void* cryptoHeap  = NULL;
static int   cryptoDevId = WOLFSSL_AUTOSAR_DEVID;

/* set once the driver mutexes exist, so a repeated Crypto_Init() does not
 * re-initialize them underneath a thread holding one */
static int cryptoInit = 0;

/* guards keyStore */
static wolfSSL_Mutex crypto_mutex;

/* guards activeJobs. Separate from crypto_mutex so a streaming job does not
 * serialize against key provisioning, and so neither lock is ever held while
 * the other is taken. */
static wolfSSL_Mutex jobs_mutex;

#ifdef WOLF_PRIVATE_KEY_ID
    /* Longest hardware key identifier and label a slot can hold. */
    #ifndef MAX_KEY_ID_LEN
        #define MAX_KEY_ID_LEN 32
    #endif
    /* 31, not 32, and the two halves of wolfCrypt disagree about why.
     * wc_AesInit_Label() accepts a label of exactly AES_MAX_LABEL_LEN (32),
     * but _InitCmac_common() copies one only when its length is strictly less
     * than sizeof(cmac->label), which is the same 32 -- and when it does not
     * copy, it leaves labelLen at 0 without failing. A 32 character label
     * would therefore work for a cipher job and reach a MAC device with no
     * label at all, which the device cannot resolve. One limit for both
     * services, set to what the stricter one can carry. */
    #ifndef MAX_KEY_LABEL_LEN
        #define MAX_KEY_LABEL_LEN (AES_MAX_LABEL_LEN - 1)
    #endif

        /* One more byte for the terminator, so the documented maximum fits. */
    #define KEY_LABEL_BUF_LEN (MAX_KEY_LABEL_LEN + 1)

    /* Enforced by the compiler, not the preprocessor: AES_MAX_LABEL_LEN is an
     * enum constant, so #if sees it as 0 and any comparison there silently
     * passes. A negative array size is a hard error wherever this header is
     * included. */
    typedef char wolfssl_autosar_label_fits[
        (MAX_KEY_LABEL_LEN < AES_MAX_LABEL_LEN) ? 1 : -1];

    /* The same for identifiers, and for the same reason it is a typedef: an
     * Aes or Cmac carries at most AES_MAX_ID_LEN bytes of identifier, so
     * raising MAX_KEY_ID_LEN past it would let a slot be provisioned with an
     * identifier that every job using it then fails to initialize with. Fail
     * the build instead of handing out unusable slots. */
    typedef char wolfssl_autosar_id_fits[
        (MAX_KEY_ID_LEN <= AES_MAX_ID_LEN) ? 1 : -1];
#endif

/* What a keystore slot holds. A slot either carries the key material itself,
 * or names a key that lives in a device and never enters RAM. */
enum {
    KEY_REF_NONE = 0,
    KEY_REF_RAW  = 1   /* the key bytes */
#ifdef WOLF_PRIVATE_KEY_ID
    ,KEY_REF_ID    = 2 /* an opaque device key identifier */
    ,KEY_REF_LABEL = 3 /* a device key label */
#endif
};

struct Keys {
    uint32 keyLen;  /* raw key length, or identifier length */
    uint32 eId;
    uint8  refType; /* KEY_REF_* */

    union {
        /* raw key */
        uint8 key[AES_MAX_KEY_SIZE/WOLFSSL_BIT_SIZE];
#ifdef WOLF_PRIVATE_KEY_ID
        uint8 id[MAX_KEY_ID_LEN];
        char  label[KEY_LABEL_BUF_LEN];
#endif
    } v;
} Keys;


/* A key as handed to the driver: either the bytes, or a name for a key in
 * hardware. Copied out of the keystore under the lock so nothing the caller
 * uses can be rewritten underneath it. */
struct KeyRef {
    uint8  refType;
    uint8  raw[AES_MAX_KEY_SIZE/WOLFSSL_BIT_SIZE];
    uint32 rawSz;
#ifdef WOLF_PRIVATE_KEY_ID
    uint8  id[MAX_KEY_ID_LEN];
    uint32 idLen;
    char   label[KEY_LABEL_BUF_LEN];
#endif
};


/* which member of a job slot's context union is live */
enum {
    JOB_CTX_NONE = 0,
    JOB_CTX_AES  = 1
#ifdef WOLFSSL_AUTOSAR_CMAC
    ,JOB_CTX_CMAC = 2
#endif
};

/* A job is bound to one service for its lifetime -- AUTOSAR ties the service
 * and the jobId together -- so the per-service contexts never coexist and can
 * share storage. 'type' says which one is live. */
struct Jobs {
    uint32 jobId;
    uint8  inUse; /* is the job slot taken */
    uint8  type;  /* JOB_CTX_* */
    union {
        Aes aes;
#ifdef WOLFSSL_AUTOSAR_CMAC
        Cmac cmac;
#endif
    } ctx;
} Jobs;

static struct Jobs activeJobs[MAX_JOBS];
static struct Keys keyStore[MAX_KEYSTORE];

/* START sequences past their first step and not yet finished with it.
 * Guarded by jobs_mutex, like the table itself. */
static int jobsStarting = 0;


/* is len a key length this build of AES supports?
 * returns 1 if usable and 0 if not */
static int ValidAesKeyLen(uint32 len)
{
#ifdef WOLFSSL_AES_128
    if (len == 16) {
        return 1;
    }
#endif
#ifdef WOLFSSL_AES_192
    if (len == 24) {
        return 1;
    }
#endif
#ifdef WOLFSSL_AES_256
    if (len == 32) {
        return 1;
    }
#endif
    (void)len;
    return 0;
}


/* Copies whatever slot 'i' holds into 'out'.
 * crypto_mutex must be held. Returns 0 on success. */
static int CopySlot(int i, struct KeyRef* out)
{
    XMEMSET(out, 0, sizeof(*out));

    switch (keyStore[i].refType) {
        case KEY_REF_RAW:
            if (keyStore[i].keyLen > sizeof(out->raw)) {
                WOLFSSL_MSG("Stored key is larger than the buffer");
                return -1;
            }
            XMEMCPY(out->raw, keyStore[i].v.key, keyStore[i].keyLen);
            out->rawSz = keyStore[i].keyLen;
            break;

    #ifdef WOLF_PRIVATE_KEY_ID
        case KEY_REF_ID:
            if (keyStore[i].keyLen > sizeof(out->id)) {
                WOLFSSL_MSG("Stored key identifier is too large");
                return -1;
            }
            XMEMCPY(out->id, keyStore[i].v.id, keyStore[i].keyLen);
            out->idLen = keyStore[i].keyLen;
            break;

        case KEY_REF_LABEL:
            XMEMCPY(out->label, keyStore[i].v.label, sizeof(out->label));
            out->label[sizeof(out->label) - 1] = '\0';
            break;
    #endif

        default:
            return -1;
    }

    out->refType = keyStore[i].refType;
    return 0;
}


/* Resolves the key of element type eId and copies it into 'out'.
 *
 * The copy is deliberate: handing back a pointer into keyStore[] would let a
 * concurrent Csm_KeyElementSet() overwrite it after the mutex is dropped but
 * before the caller has used it.
 *
 * What comes back may be key material or a name for a key in hardware; the
 * caller switches on out->refType.
 *
 * returns 0 on success
 */
static int GetKeyRef(Crypto_JobType* job, uint32 eId, struct KeyRef* out)
{
    int i, ret = 0;
    int found = 0;

    if (out == NULL) {
        WOLFSSL_MSG("Bad parameter to GetKeyRef");
        return -1;
    }
    XMEMSET(out, 0, sizeof(*out));

    if (wc_LockMutex(&crypto_mutex) != 0) {
        WOLFSSL_MSG("Unable to lock crypto mutex");
        return -1;
    }

    /* A job may name the slot holding its key element outright, which is the
     * only way to tell a cipher key from a MAC key: the specification scopes
     * element IDs per key, so both are 0x01, and resolving by element alone
     * would take whichever slot came first. Other elements -- the cipher IV --
     * keep the resolved-by-element path, their IDs being unambiguous. */
    if (job->jobPrimitiveInfo->cryIfKeyId != WOLFSSL_CSM_KEY_ID_ANY &&
            eId == (uint32)CRYPTO_KE_CIPHER_KEY) {
        uint32 named = job->jobPrimitiveInfo->cryIfKeyId;

        if (named >= MAX_KEYSTORE) {
            WOLFSSL_MSG("Named key slot is out of range");
            ret = -1;
        }
        else if (keyStore[named].refType == KEY_REF_NONE) {
            WOLFSSL_MSG("Named key slot is empty");
            ret = -1;
        }
        else if (keyStore[named].eId != eId) {
            WOLFSSL_MSG("Named key slot holds a different key element");
            ret = -1;
        }
        else if (CopySlot((int)named, out) != 0) {
            ret = -1;
        }
        else {
            found = 1;
        }

        if (wc_UnLockMutex(&crypto_mutex) != 0) {
            WOLFSSL_MSG("Unable to unlock crypto mutex");
            ret = -1;
        }
        if (ret != 0 || !found) {
            ForceZero(out, sizeof(*out));
            return -1;
        }
        return 0;
    }

#ifdef REDIRECTION_CONFIG
    /* keys should be set... */
    if (job->jobRedirectionInfoRef == NULL) {
        WOLFSSL_MSG("Issue with getting key redirection");
        wc_UnLockMutex(&crypto_mutex);
        return -1;
    }

    /* @TODO sanity checks on setup... uint8 redirectionConfig; */
    /* case labels here are runtime values, so this cannot be a switch */
    i = -1;
    if (eId == job->jobRedirectionInfoRef->inputKeyElementId) {
        if (job->jobRedirectionInfoRef->inputKeyId >= MAX_KEYSTORE) {
            WOLFSSL_MSG("Bogus input key ID redirection (too large)");
            ret = -1;
        }
        else {
            i = (int)job->jobRedirectionInfoRef->inputKeyId;
        }
    }
    else if (eId == job->jobRedirectionInfoRef->secondaryInputKeyElementId) {
        if (job->jobRedirectionInfoRef->secondaryInputKeyId >= MAX_KEYSTORE) {
            WOLFSSL_MSG("Bogus input key ID redirection (too large)");
            ret = -1;
        }
        else {
            i = (int)job->jobRedirectionInfoRef->secondaryInputKeyId;
        }
    }
    else if (eId == job->jobRedirectionInfoRef->tertiaryInputKeyElementId) {
        if (job->jobRedirectionInfoRef->tertiaryInputKeyId >= MAX_KEYSTORE) {
            WOLFSSL_MSG("Bogus input key ID redirection (too large)");
            ret = -1;
        }
        else {
            i = (int)job->jobRedirectionInfoRef->tertiaryInputKeyId;
        }
    }
    else {
        WOLFSSL_MSG("Unknown key element ID");
        ret = -1;
    }

    if (ret == 0 && i >= 0) {
        if (keyStore[i].refType == KEY_REF_NONE) {
            WOLFSSL_MSG("Redirected key slot is empty");
            ret = -1;
        }
        else if (CopySlot(i, out) != 0) {
            ret = -1;
        }
        else {
            found = 1;
        }
    }
#else
#if defined(WOLFSSL_AUTOSAR_CMAC) && \
        !defined(WOLFSSL_AUTOSAR_ALLOW_AMBIGUOUS_KEY_ELEMENT)
    /* With the MAC services built, key element 0x01 means both
     * CRYPTO_KE_CIPHER_KEY and CRYPTO_KE_MAC_KEY, so a keystore holding more
     * than one such slot cannot be resolved by element: taking the first would
     * run a MAC under a cipher key, or the reverse, and report success. Refuse
     * instead, and let the caller name the slot with
     * wolfSSL_Csm_EncryptWithKey() or wolfSSL_Csm_MacGenerateWithKey().
     *
     * One slot is unambiguous whichever service provisioned it, so the common
     * single-key ECU is unaffected. A build without the MAC services has only
     * one user of 0x01 and keeps the plain first-match scan, as does one
     * defining WOLFSSL_AUTOSAR_ALLOW_AMBIGUOUS_KEY_ELEMENT -- see Csm.h for
     * when that is safe. */
    if (eId == (uint32)CRYPTO_KE_CIPHER_KEY) {
        int matches = 0;

        for (i = 0; i < MAX_KEYSTORE; i++) {
            if (keyStore[i].eId == eId &&
                    keyStore[i].refType != KEY_REF_NONE) {
                matches++;
            }
        }

        if (matches > 1) {
            WOLFSSL_MSG("Ambiguous key element 0x01: name the slot with "
                        "wolfSSL_Csm_*WithKey()");
            ret = -1;
        }
    }
#endif

    /* Find the first slot of this key element type. A keyLength of 0 in the
     * job means "whatever the keystore holds", which is how the CSM asks for a
     * cipher key: the stored key's own length then selects AES-128/192/256. A
     * non-zero keyLength has to match exactly, and only applies to a slot that
     * holds key material -- a slot naming a key in hardware has no length the
     * driver can see. */
    for (i = 0; ret == 0 && i < MAX_KEYSTORE; i++) {
        uint32 want = job->jobPrimitiveInfo->primitiveInfo->algorithm.keyLength;

        if (keyStore[i].eId != eId ||
                keyStore[i].refType == KEY_REF_NONE) {
            continue;
        }
        if (want != 0 && keyStore[i].refType == KEY_REF_RAW &&
                keyStore[i].keyLen != want) {
            continue;
        }

        if (CopySlot(i, out) != 0) {
            ret = -1;
        }
        else {
            found = 1;
        }
        break;
    }
#endif

    if (wc_UnLockMutex(&crypto_mutex) != 0) {
        WOLFSSL_MSG("Unable to unlock crypto mutex");
        ret = -1;
    }

    if (ret == 0 && !found) {
        WOLFSSL_MSG("Unable to find an available key");
        ret = -1;
    }

    if (ret != 0) {
        ForceZero(out, sizeof(*out));
    }
    return ret;
}


/* Convenience wrapper for the places that can only use key material: copies a
 * raw key out and refuses a slot that names a key in hardware.
 * On entry *keySz is the buffer size, on success the length copied.
 * returns 0 on success */
static int GetKey(Crypto_JobType* job, uint32 eId, uint8* key, uint32* keySz)
{
    struct KeyRef kref;
    int ret;

    if (key == NULL || keySz == NULL || *keySz == 0) {
        WOLFSSL_MSG("Bad parameter to GetKey");
        return -1;
    }

    ret = GetKeyRef(job, eId, &kref);
    if (ret != 0) {
        return ret;
    }

    if (kref.refType != KEY_REF_RAW) {
        WOLFSSL_MSG("This service needs key material, not a device key name");
        ForceZero(&kref, sizeof(kref));
        return -1;
    }

    if (kref.rawSz > *keySz) {
        WOLFSSL_MSG("Key is larger than the buffer provided");
        ForceZero(&kref, sizeof(kref));
        return -1;
    }

    XMEMCPY(key, kref.raw, kref.rawSz);
    *keySz = kref.rawSz;
    ForceZero(&kref, sizeof(kref));
    return 0;
}


/* A START is not one step: it copies key material out of the keystore, checks
 * it, reads cryptoDevId and only then claims a slot and builds the context.
 * Crypto_Init() decides whether a reconfiguration is safe by looking at slot
 * ownership, which says nothing about a START that has not reached its slot
 * yet -- so without a gate the whole of Crypto_Init() could run inside that
 * window, wipe the keystore and publish a new heap and devId, and leave the
 * START building a context for the newly configured device out of the previous
 * configuration's key.
 *
 * These make the window itself visible to that check, which is all it needs:
 * Crypto_Init() refuses while a START is in progress, exactly as it refuses
 * while a job holds a slot. Nothing waits on anything, so the gate cannot
 * deadlock, and a START holding it is also why the unlocked cryptoDevId read
 * below has no writer to race with.
 *
 * EnterStart() returns 0 when the gate is held. */
static int EnterStart(void)
{
    if (wc_LockMutex(&jobs_mutex) != 0) {
        WOLFSSL_MSG("Unable to lock jobs mutex");
        return -1;
    }
    jobsStarting++;
    if (wc_UnLockMutex(&jobs_mutex) != 0) {
        WOLFSSL_MSG("Unable to unlock jobs mutex");
    }
    return 0;
}


static void LeaveStart(void)
{
    if (wc_LockMutex(&jobs_mutex) != 0) {
        /* Leaving the count raised is the safe direction: it refuses
         * reconfiguration rather than allowing one over a live job. */
        WOLFSSL_MSG("Unable to lock jobs mutex");
        return;
    }
    if (jobsStarting > 0) {
        jobsStarting--;
    }
    if (wc_UnLockMutex(&jobs_mutex) != 0) {
        WOLFSSL_MSG("Unable to unlock jobs mutex");
    }
}


/* Finds the slot owned by jobId, or NULL.
 * jobs_mutex must be held by the caller. */
static struct Jobs* FindJobSlot(uint32 jobId)
{
    int i;

    for (i = 0; i < MAX_JOBS; i++) {
        if (activeJobs[i].inUse == 1 && activeJobs[i].jobId == jobId) {
            return &activeJobs[i];
        }
    }
    return NULL;
}


/* Frees whichever context a slot holds and marks it unused.
 * jobs_mutex must be held by the caller. */
static void ReleaseJobSlot(struct Jobs* slot)
{
    if (slot->type == JOB_CTX_AES) {
        wc_AesFree(&slot->ctx.aes);
    }
#ifdef WOLFSSL_AUTOSAR_CMAC
    else if (slot->type == JOB_CTX_CMAC) {
        (void)wc_CmacFree(&slot->ctx.cmac);
    }
#endif
    slot->type  = JOB_CTX_NONE;
    slot->inUse = 0;
    slot->jobId = 0;
}


/* Claims a slot for jobId, or NULL if the table is full.
 *
 * A START on a jobId that already owns a slot restarts it: the previous
 * context is freed and the slot reused. Claiming a second slot for the same
 * jobId would be worse than either -- FindJobSlot() returns the lowest match,
 * so UPDATE and FINISH would keep using the stale context while the new one
 * leaked, and a stale raw-key context would happily encrypt under the previous
 * key and report success. The START paths retire the old slot before they
 * resolve a key, so by the time this runs there is normally nothing to find;
 * it stays because this is the only place that may hand out a slot, and that
 * invariant should not depend on a caller.
 *
 * jobs_mutex must be held by the caller. */
static struct Jobs* ClaimJobSlot(uint32 jobId)
{
    int i;
    struct Jobs* slot = FindJobSlot(jobId);

    if (slot != NULL) {
        WOLFSSL_MSG("START on a job that is already active, restarting it");
        ReleaseJobSlot(slot);
    }
    else {
        for (i = 0; i < MAX_JOBS; i++) {
            if (activeJobs[i].inUse == 0) {
                slot = &activeJobs[i];
                break;
            }
        }
    }

    if (slot == NULL) {
        return NULL;
    }

    slot->inUse = 1;
    slot->jobId = jobId;
    slot->type  = JOB_CTX_NONE;
    return slot;
}


/* Returned context pointers outlive the lock. That is safe because a slot is
 * owned by exactly one jobId from START to FINISH, and AUTOSAR gives a job a
 * single owner; the lock is what keeps two jobs from claiming the same slot or
 * from seeing a half-updated table. */

/* returns a pointer to the Aes struct on success, NULL on failure */
static Aes* GetAesStruct(Crypto_JobType* job)
{
    struct Jobs* slot;
    Aes* aes = NULL;

    if (wc_LockMutex(&jobs_mutex) != 0) {
        WOLFSSL_MSG("Unable to lock jobs mutex");
        return NULL;
    }

    slot = FindJobSlot(job->jobId);
    if (slot != NULL && slot->type == JOB_CTX_AES) {
        aes = &slot->ctx.aes;
    }

    if (wc_UnLockMutex(&jobs_mutex) != 0) {
        WOLFSSL_MSG("Unable to unlock jobs mutex");
        return NULL;
    }
    return aes;
}


/* Claims a slot and initializes its AES context.
 *
 * With key material this is wc_AesInit() and the caller follows with
 * wc_AesSetKey(). With a device key name it is wc_AesInit_Id() or
 * wc_AesInit_Label(), which leave the software key schedule empty on purpose:
 * the context still reaches its crypto callback, and only fails if it falls
 * through to a software path -- exactly the case that would otherwise encrypt
 * under an all-zero key.
 *
 * returns a pointer to the Aes struct on success, NULL on failure */
static Aes* NewAesStruct(Crypto_JobType* job, const struct KeyRef* kref)
{
    struct Jobs* slot;
    int ret = 0;

    if (wc_LockMutex(&jobs_mutex) != 0) {
        WOLFSSL_MSG("Unable to lock jobs mutex");
        return NULL;
    }

    slot = ClaimJobSlot(job->jobId);
    if (slot == NULL) {
        WOLFSSL_MSG("No free job slot, consider raising MAX_JOBS");
    }
    else {
#ifdef WOLF_PRIVATE_KEY_ID
        if (kref != NULL && kref->refType == KEY_REF_ID) {
            /* the cast drops const: wc_AesInit_Id() takes a mutable pointer
             * but does not write through it */
            ret = wc_AesInit_Id(&slot->ctx.aes, (unsigned char*)kref->id,
                    (int)kref->idLen, cryptoHeap, cryptoDevId);
        }
        else if (kref != NULL && kref->refType == KEY_REF_LABEL) {
            ret = wc_AesInit_Label(&slot->ctx.aes, kref->label, cryptoHeap,
                    cryptoDevId);
        }
        else
#endif
        {
            ret = wc_AesInit(&slot->ctx.aes, cryptoHeap, cryptoDevId);
        }

        if (ret != 0) {
            WOLFSSL_MSG("Error initializing AES structure");
            slot->inUse = 0;
            slot->jobId = 0;
            slot = NULL;
        }
        else {
            slot->type = JOB_CTX_AES;
        }
    }

    if (wc_UnLockMutex(&jobs_mutex) != 0) {
        WOLFSSL_MSG("Unable to unlock jobs mutex");
        return NULL;
    }
    (void)kref;
    return (slot == NULL) ? NULL : &slot->ctx.aes;
}


#ifdef WOLFSSL_AUTOSAR_CMAC
/* returns a pointer to the Cmac struct on success, NULL on failure */
static Cmac* GetCmacStruct(Crypto_JobType* job)
{
    struct Jobs* slot;
    Cmac* cmac = NULL;

    if (wc_LockMutex(&jobs_mutex) != 0) {
        WOLFSSL_MSG("Unable to lock jobs mutex");
        return NULL;
    }

    slot = FindJobSlot(job->jobId);
    if (slot != NULL && slot->type == JOB_CTX_CMAC) {
        cmac = &slot->ctx.cmac;
    }

    if (wc_UnLockMutex(&jobs_mutex) != 0) {
        WOLFSSL_MSG("Unable to unlock jobs mutex");
        return NULL;
    }
    return cmac;
}


/* Claims a slot and initializes its CMAC context.
 *
 * wc_InitCmac() takes the key, so unlike AES there is no separate set-key --
 * which is also why a device key name goes in here rather than afterwards.
 * With a name, _InitCmac_common() stores it on the Cmac, offers the operation
 * to the crypto callback, and only reaches its "key must not be NULL" check if
 * the callback declines. That ordering is what makes a named MAC key
 * fail-closed: a device that will not do the work gets BAD_FUNC_ARG rather
 * than a CMAC under something else.
 *
 * returns a pointer to the Cmac struct on success, NULL on failure */
static Cmac* NewCmacStruct(Crypto_JobType* job, const struct KeyRef* kref)
{
    struct Jobs* slot;
    int ret;

    if (wc_LockMutex(&jobs_mutex) != 0) {
        WOLFSSL_MSG("Unable to lock jobs mutex");
        return NULL;
    }

    slot = ClaimJobSlot(job->jobId);
    if (slot == NULL) {
        WOLFSSL_MSG("No free job slot, consider raising MAX_JOBS");
        ret = -1;
    }
#ifdef WOLF_PRIVATE_KEY_ID
    else if (kref->refType == KEY_REF_ID) {
        /* the cast drops const: wc_InitCmac_Id() takes a mutable pointer but
         * does not write through it */
        ret = wc_InitCmac_Id(&slot->ctx.cmac, NULL, 0, WC_CMAC_AES, NULL,
                (unsigned char*)kref->id, (int)kref->idLen, cryptoHeap,
                cryptoDevId);
    }
    else if (kref->refType == KEY_REF_LABEL) {
        ret = wc_InitCmac_Label(&slot->ctx.cmac, NULL, 0, WC_CMAC_AES, NULL,
                kref->label, cryptoHeap, cryptoDevId);
    }
#endif
    else {
        ret = wc_InitCmac_ex(&slot->ctx.cmac, kref->raw, kref->rawSz,
                WC_CMAC_AES, NULL, cryptoHeap, cryptoDevId);
    }

    if (slot != NULL && ret != 0) {
        /* Free it even though init failed: initialization can fail after
         * taking the Aes inside the Cmac, and on a devId build after the
         * callback has allocated for it. */
        WOLFSSL_MSG("Error initializing CMAC structure");
        (void)wc_CmacFree(&slot->ctx.cmac);
        slot->inUse = 0;
        slot->jobId = 0;
        slot = NULL;
    }
    else if (slot != NULL) {
        slot->type = JOB_CTX_CMAC;
    }

    if (wc_UnLockMutex(&jobs_mutex) != 0) {
        WOLFSSL_MSG("Unable to unlock jobs mutex");
        return NULL;
    }
    return (slot == NULL) ? NULL : &slot->ctx.cmac;
}
#endif /* WOLFSSL_AUTOSAR_CMAC */


/* free's up the job slot, and whichever context it holds
 * returns 0 on success and -1 if the job owns no slot */
static int FreeJobSlot(Crypto_JobType* job)
{
    struct Jobs* slot;
    int ret = 0;

    if (wc_LockMutex(&jobs_mutex) != 0) {
        WOLFSSL_MSG("Unable to lock jobs mutex");
        return -1;
    }

    slot = FindJobSlot(job->jobId);
    if (slot == NULL) {
        WOLFSSL_MSG("Error finding job slot");
        ret = -1;
    }
    else {
        ReleaseJobSlot(slot);
    }

    if (wc_UnLockMutex(&jobs_mutex) != 0) {
        WOLFSSL_MSG("Unable to unlock jobs mutex");
        ret = -1;
    }
    return ret;
}


/* The START half of a cipher job: resolve the key, check it, claim a slot and
 * build the context. Separated out so the reconfiguration gate covers every
 * way it can leave. Returns E_OK on success. */
static Std_ReturnType StartCbcJob(Crypto_JobType* job, int encrypt)
{
    Aes* aes;
    /* local copies so the keystore mutex is not held while they are used */
    struct KeyRef kref;
    uint8  iv[WC_AES_BLOCK_SIZE];
    uint32 ivSz = (uint32)sizeof(iv);

    /* A restart retires the old context first, before anything that can fail.
     *
     * ClaimJobSlot() also releases a slot this jobId already owns, but it runs
     * only once the key and IV have been resolved and checked -- so a restart
     * that fails before it, on a key the keystore no longer holds or one whose
     * length is not a valid AES key length, used to leave the previous context
     * in place: the START reported E_NOT_OK while an UPDATE carried on under
     * the old key, and the slot stayed claimed, which now also blocks
     * reconfiguration. Dropping it up front means a failed restart leaves
     * nothing, like any other failed job. */
    (void)FreeJobSlot(job);

    if (GetKeyRef(job, CRYPTO_KE_CIPHER_KEY, &kref) != 0) {
        WOLFSSL_MSG("Crypto error with getting a key");
        return E_NOT_OK;
    }

    /* Only a slot holding key material has a length to check; a device
     * key name says nothing about the key behind it. */
    if (kref.refType == KEY_REF_RAW && !ValidAesKeyLen(kref.rawSz)) {
        WOLFSSL_MSG("Key found is not a supported AES key length");
        ForceZero(&kref, sizeof(kref));
        return E_NOT_OK;
    }

    /* A named key is only safe while something refuses to run without the
     * key: the software key schedule is left empty on purpose, so a job
     * that reaches a software path would otherwise encrypt under an
     * all-zero key and report success.
     *
     * Three ways that promise can be void, all refused here rather than
     * trusted:
     *   - no device configured, so the name resolves to nothing;
     *   - wolfCrypt's key-is-set check compiled out, by
     *     WOLFSSL_NO_AES_KEY_SET_CHECK or by this build not defining
     *     WOLFSSL_AES_REQUIRE_KEY_SET;
     *   - a back end that replaces the AES mode entry points, which is what
     *     WC_AES_KEY_SET_CHECK_UNSUPPORTED in aes.h marks -- STM32, Freescale
     *     LTC/MMCAU, CryptoCell, SCE, SiLabs SE, TI, CAAM, PSA, Xilinx and the
     *     rest. There the check is not merely off by default: those
     *     wc_AesCbcEncrypt()/Decrypt() implementations never consult
     *     WC_AES_KEY_IS_SET, so after the crypto callback declines they go
     *     straight to the hardware with whatever key state the context has.
     *     Forcing WOLFSSL_AES_REQUIRE_KEY_SET on buys nothing there -- it only
     *     makes the macro true -- so the refusal cannot be keyed on the macro
     *     alone. */
    if (kref.refType != KEY_REF_RAW) {
        if (cryptoDevId == INVALID_DEVID) {
            WOLFSSL_MSG("Named key with no device configured, refusing");
            ForceZero(&kref, sizeof(kref));
            return E_NOT_OK;
        }
    #if !defined(WOLFSSL_AES_REQUIRE_KEY_SET) || \
            defined(WC_AES_KEY_SET_CHECK_UNSUPPORTED)
        WOLFSSL_MSG("Named cipher key needs wolfCrypt's key-is-set check, "
                    "which this build or back end does not enforce, refusing");
        ForceZero(&kref, sizeof(kref));
        return E_NOT_OK;
    #endif
    }

    /* The IV is not secret and is always material, never a name. */
    if (GetKey(job, CRYPTO_KE_CIPHER_IV, iv, &ivSz) != 0) {
        WOLFSSL_MSG("Crypto error with getting an IV");
        ForceZero(&kref, sizeof(kref));
        return E_NOT_OK;
    }

    if (ivSz < WC_AES_BLOCK_SIZE) {
        WOLFSSL_MSG("Error IV is too small");
        ForceZero(&kref, sizeof(kref));
        return E_NOT_OK;
    }

    aes = NewAesStruct(job, &kref);
    if (aes == NULL) {
        WOLFSSL_MSG("Unable to get AES structure for use");
        ForceZero(&kref, sizeof(kref));
        return E_NOT_OK;
    }

    if (kref.refType == KEY_REF_RAW) {
        if (wc_AesSetKey(aes, kref.raw, kref.rawSz, iv, encrypt) != 0) {
            (void)FreeJobSlot(job);
            WOLFSSL_MSG("Crypto error setting up AES key");
            ForceZero(&kref, sizeof(kref));
            return E_NOT_OK;
        }
    }
    else {
        /* The device holds the key, so there is nothing to expand, only
         * the IV to record. The direction travels with each operation. */
        if (wc_AesSetIV(aes, iv) != 0) {
            (void)FreeJobSlot(job);
            WOLFSSL_MSG("Crypto error setting the AES IV");
            ForceZero(&kref, sizeof(kref));
            return E_NOT_OK;
        }
    }

    /* whatever was needed is in the Aes struct or stayed in the device */
    ForceZero(&kref, sizeof(kref));

    return E_OK;
}


/* returns E_OK on success */
Std_ReturnType wolfSSL_Crypto_CBC(Crypto_JobType* job)
{
    Std_ReturnType ret = E_OK;
    int encrypt;

    encrypt = (job->jobPrimitiveInfo->primitiveInfo->service == CRYPTO_ENCRYPT)
        ? AES_ENCRYPTION : AES_DECRYPTION;

    /* check if key should be set */
    if ((job->jobPrimitiveInputOutput.mode & CRYPTO_OPERATIONMODE_START) != 0) {
        Std_ReturnType sret;

        if (EnterStart() != 0) {
            return E_NOT_OK;
        }
        sret = StartCbcJob(job, encrypt);
        LeaveStart();
        if (sret != E_OK) {
            return sret;
        }
    }

    if ((job->jobPrimitiveInputOutput.mode & CRYPTO_OPERATIONMODE_UPDATE)
            != 0) {
        Aes* aes = GetAesStruct(job);

        if (aes == NULL) {
            WOLFSSL_MSG("Error finding AES structure");
            return E_NOT_OK;
        }

        /* Free the slot on failure. A job that fails mid-stream is not going
         * to send a FINISH, and leaving the slot claimed would both leak it
         * and leave a stale context for the next START with this jobId. A
         * named key the device will not handle fails exactly here. */
        if (encrypt == AES_ENCRYPTION) {
            if (wc_AesCbcEncrypt(aes, job->jobPrimitiveInputOutput.outputPtr,
                    job->jobPrimitiveInputOutput.inputPtr,
                    job->jobPrimitiveInputOutput.inputLength) != 0) {
                WOLFSSL_MSG("AES-CBC encrypt error");
                (void)FreeJobSlot(job);
                return E_NOT_OK;
            }
        }
        else {
            if (wc_AesCbcDecrypt(aes, job->jobPrimitiveInputOutput.outputPtr,
                    job->jobPrimitiveInputOutput.inputPtr,
                    job->jobPrimitiveInputOutput.inputLength) != 0) {
                WOLFSSL_MSG("AES-CBC decrypt error");
                (void)FreeJobSlot(job);
                return E_NOT_OK;
            }
        }
    }

    if ((job->jobPrimitiveInputOutput.mode & CRYPTO_OPERATIONMODE_FINISH)
            != 0) {
        if (FreeJobSlot(job) != 0) {
            WOLFSSL_MSG("FINISH on a job that was never started");
            ret = E_NOT_OK;
        }
    }

    return ret;
}


#ifdef WOLFSSL_AUTOSAR_CMAC
/* The START half of a MAC job, extracted for the same reason as
 * StartCbcJob(): the reconfiguration gate has to cover every exit.
 * Returns E_OK on success. */
static Std_ReturnType StartCmacJob(Crypto_JobType* job)
{
    struct KeyRef kref;
    Cmac* cmac;

    /* Retired up front for the reason StartCbcJob() gives. */
    (void)FreeJobSlot(job);

    if (GetKeyRef(job, CRYPTO_KE_MAC_KEY, &kref) != 0) {
        WOLFSSL_MSG("Crypto error with getting a MAC key");
        return E_NOT_OK;
    }

    /* Only key material has a length to check; a device key name says
     * nothing about the key behind it. */
    if (kref.refType == KEY_REF_RAW && !ValidAesKeyLen(kref.rawSz)) {
        WOLFSSL_MSG("Key found is not a supported AES key length");
        ForceZero(&kref, sizeof(kref));
        return E_NOT_OK;
    }

    /* A named key needs a device to resolve it. Unlike the cipher path
     * this does not also need wolfCrypt's key-is-set check: CMAC
     * initialization refuses a NULL key once the callback has declined,
     * so the software fall-through cannot run under a zero key. */
    if (kref.refType != KEY_REF_RAW && cryptoDevId == INVALID_DEVID) {
        WOLFSSL_MSG("Named MAC key with no device configured, refusing");
        ForceZero(&kref, sizeof(kref));
        return E_NOT_OK;
    }

    /* CMAC initialization consumes the key, so this both claims the slot
     * and sets the key -- or the name of one. */
    cmac = NewCmacStruct(job, &kref);
    ForceZero(&kref, sizeof(kref));
    if (cmac == NULL) {
        WOLFSSL_MSG("Unable to get CMAC structure for use");
        return E_NOT_OK;
    }

    return E_OK;
}


/* AES-CMAC generate and verify.
 *
 * Verify takes its length in BITS, as the specification defines macLength:
 * secondaryInputLength carries the bit count, which this function rounds to
 * bytes and compares with the trailing partial byte masked. Generate reports
 * the length it produced in bytes through outputLengthPtr.
 *
 * returns E_OK on success */
Std_ReturnType wolfSSL_Crypto_CMAC(Crypto_JobType* job)
{
    Cmac* cmac;
    int generate;

    generate =
        (job->jobPrimitiveInfo->primitiveInfo->service == CRYPTO_MACGENERATE);

    if ((job->jobPrimitiveInputOutput.mode & CRYPTO_OPERATIONMODE_START) != 0) {
        Std_ReturnType sret;

        if (EnterStart() != 0) {
            return E_NOT_OK;
        }
        sret = StartCmacJob(job);
        LeaveStart();
        if (sret != E_OK) {
            return sret;
        }
    }

    if ((job->jobPrimitiveInputOutput.mode & CRYPTO_OPERATIONMODE_UPDATE)
            != 0) {
        cmac = GetCmacStruct(job);
        if (cmac == NULL) {
            WOLFSSL_MSG("Error finding CMAC structure");
            return E_NOT_OK;
        }

        if (wc_CmacUpdate(cmac, job->jobPrimitiveInputOutput.inputPtr,
                job->jobPrimitiveInputOutput.inputLength) != 0) {
            WOLFSSL_MSG("AES-CMAC update error");
            (void)FreeJobSlot(job);
            return E_NOT_OK;
        }
    }

    /* the tag only exists once the whole message has been absorbed */
    if ((job->jobPrimitiveInputOutput.mode & CRYPTO_OPERATIONMODE_FINISH)
            != 0) {
        uint8  tag[WC_CMAC_TAG_MAX_SZ];
        uint32 tagSz = (uint32)sizeof(tag);
        word32 outSz = (word32)sizeof(tag);
        Std_ReturnType ret = E_OK;

        cmac = GetCmacStruct(job);
        if (cmac == NULL) {
            WOLFSSL_MSG("Error finding CMAC structure");
            return E_NOT_OK;
        }

        /* NoFree so FreeJobSlot() stays the single owner of the context */
        if (wc_CmacFinalNoFree(cmac, tag, &outSz) != 0) {
            WOLFSSL_MSG("AES-CMAC final error");
            (void)FreeJobSlot(job);
            return E_NOT_OK;
        }
        tagSz = (uint32)outSz;

        if (generate) {
            uint32* outLen = job->jobPrimitiveInputOutput.outputLengthPtr;

            if (job->jobPrimitiveInputOutput.outputPtr == NULL ||
                    outLen == NULL) {
                WOLFSSL_MSG("No output buffer for the MAC");
                ret = E_NOT_OK;
            }
            else if (*outLen < tagSz) {
                WOLFSSL_MSG("MAC output buffer is too small");
                ret = E_NOT_OK;
            }
            else {
                XMEMCPY(job->jobPrimitiveInputOutput.outputPtr, tag, tagSz);
                /* unlike the cipher services, MAC generate does report the
                 * length produced */
                *outLen = tagSz;
            }
        }
        else {
            const uint8* expect =
                job->jobPrimitiveInputOutput.secondaryInputPtr;
            uint32 expectSz =
                job->jobPrimitiveInputOutput.secondaryInputLength;
            Crypto_VerifyResultType* verify =
                job->jobPrimitiveInputOutput.verifyPtr;

            /* secondaryInputLength is a BIT count here, as the Csm
             * specification defines macLength. Converting in the driver keeps
             * one place that knows the unit: Csm_MacVerify() passes the
             * caller's bits through, and the wolfSSL extension, which is
             * byte-based, multiplies. */
            uint32 expectBits = expectSz;
            uint32 full = expectBits / 8;
            uint32 rem  = expectBits % 8;

            expectSz = (expectBits + 7) / 8;

            if (expect == NULL || verify == NULL) {
                WOLFSSL_MSG("No MAC or verify result pointer supplied");
                ret = E_NOT_OK;
            }
            else if (expectBits < (uint32)WOLFSSL_AUTOSAR_MAC_MIN_SZ * 8U ||
                    expectBits > tagSz * 8U) {
                /* Bounded in BITS, before the rounding above. Comparing the
                 * rounded byte count instead would accept anything from 17
                 * bits upwards against a 3 byte floor -- a 17 bit tag is
                 * guessed with probability 2^-17, not the 2^-24 the floor is
                 * documented to give.
                 *
                 * A tag this short is forged by guessing, so refuse it rather
                 * than report CRYPTO_E_VER_OK on a few bits of luck. See
                 * WOLFSSL_AUTOSAR_MAC_MIN_SZ in Csm.h for why the floor is
                 * what it is, and how to raise it. The upper bound is the tag,
                 * so a byte count passed where bits belong is rejected rather
                 * than read past the caller's buffer. */
                WOLFSSL_MSG("MAC length to compare is out of range");
                ret = E_NOT_OK;
            }
            else {
                /* A truncated MAC compares against the leading bits. Whole
                 * bytes first, then the top 'rem' bits of the next one under
                 * a mask -- SecOC profile 1's 24 bits land on a byte boundary,
                 * but the specification does not require that. */
                int diff = ConstantCompare(tag, expect, (int)full);

                if (rem != 0) {
                    uint8 mask = (uint8)(0xFFu << (8 - rem));

                    diff |= (int)((tag[full] ^ expect[full]) & mask);
                }

                *verify = (diff == 0) ? CRYPTO_E_VER_OK : CRYPTO_E_VER_NOT_OK;
            }
        }

        ForceZero(tag, sizeof(tag));
        (void)FreeJobSlot(job);
        return ret;
    }

    return E_OK;
}
#endif /* WOLFSSL_AUTOSAR_CMAC */


/* returns E_OK on success and E_NOT_OK on failure */
Std_ReturnType wolfSSL_Crypto(Crypto_JobType* job)
{
    Std_ReturnType ret = E_OK;

    WOLFSSL_ENTER("wolfSSL_Crypto");

    /* switch on encryption type */
    switch (job->jobPrimitiveInfo->primitiveInfo->algorithm.mode) {
        case CRYPTO_ALGOMODE_CBC:
            ret = wolfSSL_Crypto_CBC(job);
            break;

        case CRYPTO_ALGOMODE_NOT_SET:
            WOLFSSL_MSG("Encrypt algo mode not set!");
            ret = E_NOT_OK;
            break;

#ifdef WOLFSSL_AUTOSAR_CMAC
        case CRYPTO_ALGOMODE_CMAC:
            /* MAC jobs are routed straight to wolfSSL_Crypto_CMAC by
             * Crypto_ProcessJob; reaching here means a cipher service was
             * asked for with a MAC mode. */
            WOLFSSL_MSG("CMAC is not a cipher mode");
            ret = E_NOT_OK;
            break;
#endif

        default:
            WOLFSSL_MSG("Unsupported encryption mode");
            ret = E_NOT_OK;
            break;
    }

    WOLFSSL_LEAVE("wolfSSL_Crypto", ret);
    return ret;
}

static WC_RNG rng;
static wolfSSL_Mutex rngMutex;
static volatile byte rngInit = 0;

/* returns E_OK on success */
Std_ReturnType wolfSSL_Crypto_RNG(Crypto_JobType* job)
{
    int ret;

    uint8  *out   = job->jobPrimitiveInputOutput.outputPtr;
    uint32 *outSz = job->jobPrimitiveInputOutput.outputLengthPtr;

    if (outSz == NULL || out == NULL) {
        WOLFSSL_MSG("Bad parameter passed into wolfSSL_Crypto_RNG");
        return E_NOT_OK;
    }

    if (wc_LockMutex(&rngMutex) != 0) {
        WOLFSSL_MSG("Error locking RNG mutex");
        return E_NOT_OK;
    }

    if (rngInit == 0) {
        ret = wc_InitRng_ex(&rng, cryptoHeap, cryptoDevId);
        if (ret != 0) {
            WOLFSSL_MSG("Error initializing RNG");
            wc_UnLockMutex(&rngMutex);
            return E_NOT_OK;
        }
        rngInit = 1;
    }

    ret = wc_RNG_GenerateBlock(&rng, out, *outSz);
    if (ret != 0) {
        WOLFSSL_MSG("Unable to generate random values");
        ret = wc_FreeRng(&rng);
        if (ret != 0) {
            WOLFSSL_MSG("Error free'ing RNG");
        }
        rngInit = 0;
        wc_UnLockMutex(&rngMutex);
        return E_NOT_OK;
    }

    if (wc_UnLockMutex(&rngMutex) != 0) {
        WOLFSSL_MSG("Error unlocking RNG mutex");
        return E_NOT_OK;
    }

    return E_OK;
}


/* returns E_OK on success and E_NOT_OK on failure */
Std_ReturnType Crypto_ProcessJob(uint32 objectId, Crypto_JobType* job)
{
    Std_ReturnType ret = E_OK;
    (void)objectId;

    WOLFSSL_ENTER("Crypto_ProcessJob");
    if (job == NULL) {
        WOLFSSL_MSG("Bad parameter passed to Crypto_ProcessJob");
        ret = E_NOT_OK;
    }

    /* only handle synchronous jobs */
    if (ret == E_OK &&
            job->jobPrimitiveInfo->processingType != CRYPTO_PROCESSING_SYNC) {
        WOLFSSL_MSG("Crypto only supporting synchronous jobs");
        ret = E_NOT_OK;
    }

    if (ret == E_OK) {
        job->jobState = CRYPTO_JOBSTATE_ACTIVE;
        switch (job->jobPrimitiveInfo->primitiveInfo->service) {
            case CRYPTO_ENCRYPT:
                ret = wolfSSL_Crypto(job);
                break;

            case CRYPTO_DECRYPT:
                ret = wolfSSL_Crypto(job);
                break;

            case CRYPTO_RANDOMGENERATE:
                ret = wolfSSL_Crypto_RNG(job);
                break;

#ifdef WOLFSSL_AUTOSAR_CMAC
            case CRYPTO_MACGENERATE:
            case CRYPTO_MACVERIFY:
                ret = wolfSSL_Crypto_CMAC(job);
                break;
#endif

            default:
                WOLFSSL_MSG("Unsupported Crypto service");
                ret = E_NOT_OK;
                break;
        }
        job->jobState = CRYPTO_JOBSTATE_IDLE;
    }

    WOLFSSL_LEAVE("Crypto_ProcessJob", ret);
    return ret;
}


/* Brings up the keystore, the job table and the driver mutexes, and records
 * the heap hint and device ID the driver gives every wolfCrypt context it
 * creates. A NULL config selects the default allocator and software.
 *
 * Safe to call again: a second call re-reads the configuration. The mutexes
 * are created once, because re-initializing a live mutex is undefined for
 * pthreads and leaks the previous object on the ports where wc_InitMutex()
 * allocates one. Everything the old configuration built is torn down under
 * the lock that protects it. */
/* Releases the slot held by job->jobId and frees the context in it.
 *
 * This is the way out for a job that will never send its FINISH: a slot is
 * otherwise held for the life of the ECU, and Crypto_Init() refuses to
 * reconfigure while one is. Freeing the context here is safe for the same
 * reason FINISH is -- AUTOSAR gives a job one owner, and that owner is not
 * driving the job and cancelling it at the same time. It is not safe against
 * another thread mid-UPDATE on this jobId, which is why Crypto_Init() refuses
 * instead of doing this behind the caller's back.
 *
 * returns E_OK when a slot was released, E_NOT_OK when the job held none */
Std_ReturnType Crypto_CancelJob(uint32 objectId, Crypto_JobType* job)
{
    struct Jobs* slot;
    Std_ReturnType ret = E_OK;

    (void)objectId;

    if (job == NULL) {
        WOLFSSL_MSG("Crypto_CancelJob called with no job");
        return E_NOT_OK;
    }

    if (cryptoInit != 1) {
        WOLFSSL_MSG("Crypto_CancelJob before Crypto_Init");
        return E_NOT_OK;
    }

    if (wc_LockMutex(&jobs_mutex) != 0) {
        WOLFSSL_MSG("Unable to lock jobs mutex");
        return E_NOT_OK;
    }

    slot = FindJobSlot(job->jobId);
    if (slot == NULL) {
        /* Nothing to cancel: the job was never started, has already been
         * finished, or failed mid-stream and released its own slot. */
        WOLFSSL_MSG("Cancel on a job that holds no slot");
        ret = E_NOT_OK;
    }
    else {
        ReleaseJobSlot(slot);
    }

    if (wc_UnLockMutex(&jobs_mutex) != 0) {
        WOLFSSL_MSG("Unable to unlock jobs mutex");
        ret = E_NOT_OK;
    }

    if (ret == E_OK) {
        job->jobState = CRYPTO_JOBSTATE_IDLE;
    }
    return ret;
}


void Crypto_Init(const Crypto_ConfigType* config)
{
    /* Mutexes exist for the lifetime of the process once created. Guarded by
     * a plain flag: the first Crypto_Init() runs before there is any other
     * thread to race with, which is the same assumption AUTOSAR makes of
     * Csm_Init(). */
    if (cryptoInit == 0) {
        /* All three or none. Logging a failure and carrying on would lock an
         * uninitialized mutex immediately below, and setting cryptoInit anyway
         * would make every later Csm_Init() skip the retry. Returning leaves
         * cryptoInit clear, so a subsequent call tries again -- which is the
         * only recovery available, Crypto_Init() being void in AUTOSAR with
         * nowhere to report this. */
        if (wc_InitMutex(&crypto_mutex) != 0) {
            WOLFSSL_MSG("Issues setting up crypto mutex");
            return;
        }
        if (wc_InitMutex(&jobs_mutex) != 0) {
            WOLFSSL_MSG("Issues setting up jobs mutex");
            (void)wc_FreeMutex(&crypto_mutex);
            return;
        }
        if (wc_InitMutex(&rngMutex) != 0) {
            WOLFSSL_MSG("Error initializing RNG mutex");
            (void)wc_FreeMutex(&jobs_mutex);
            (void)wc_FreeMutex(&crypto_mutex);
            return;
        }
        cryptoInit = 1;
    }

    /* Tear the old configuration down and publish the new one while holding
     * every lock its readers use, so a job cannot straddle the two.
     *
     * cryptoHeap and cryptoDevId are read by NewAesStruct()/NewCmacStruct()
     * under jobs_mutex and by the RNG under rngMutex, so publishing them
     * outside both would let a concurrent Csm_RandomGenerate() recreate the
     * DRBG from the old values just after it was freed, or an AES context take
     * one field from each configuration.
     *
     * Lock order is jobs_mutex, rngMutex, crypto_mutex, and nothing else in
     * the driver holds more than one at a time, so this cannot deadlock. */
    if (wc_LockMutex(&jobs_mutex) != 0) {
        WOLFSSL_MSG("Unable to lock jobs mutex");
        return;
    }

    /* Refuse the whole re-init while any job owns a slot, or is on its way to
     * one.
     *
     * Freeing those contexts here was worse than leaving them: GetAesStruct()
     * and GetCmacStruct() hand the context pointer out and release
     * jobs_mutex, so wc_AesCbcEncrypt() and wc_CmacUpdate() run unlocked. A
     * concurrent Csm_Init() calling wc_AesFree() on the same context is a
     * use-after-free, and the job could still report E_OK having encrypted
     * under zeroed state. Holding jobs_mutex across the whole operation
     * instead would serialize every SW-C against every other, which is what
     * the separate mutexes exist to avoid.
     *
     * So this refuses rather than races. The caller's way out is to FINISH
     * each open job, or Csm_CancelJob() the ones it has abandoned, and call
     * Csm_Init() again; a job that failed mid-stream has already released its
     * slot. The previous configuration stays in force meanwhile, which is the
     * safe direction -- nothing is half-applied -- and because Csm_Init()
     * returns void, the refusal is reported to the DET as CSM_E_INIT_FAILED
     * rather than only logged. */
    {
        int i;
        int busy = (jobsStarting != 0);

        for (i = 0; !busy && i < MAX_JOBS; i++) {
            if (activeJobs[i].inUse == 1) {
                busy = 1;
            }
        }

        if (busy) {
            WOLFSSL_MSG("Csm_Init refused: a job is still open, FINISH or "
                        "cancel it first");
            if (wc_UnLockMutex(&jobs_mutex) != 0) {
                WOLFSSL_MSG("Unable to unlock jobs mutex");
            }
        #ifndef NO_WOLFSSL_AUTOSAR_CSM
            /* ReportToDET() lives in csm.c, so a build that brings its own
             * Csm and compiles only this driver (NO_WOLFSSL_AUTOSAR_CSM) does
             * not have it -- and could not report as module 110 anyway, that
             * being the Csm it is not providing. Such a stack's own Csm_Init()
             * does its own DET reporting; the log line above stands either
             * way. */
            ReportToDET(WOLFSSL_CSM_MODULE_ID, 0, WOLFSSL_CSM_API_ID_INIT,
                    WOLFSSL_CSM_E_INIT_FAILED);
        #endif
            return;
        }
    }

    if (wc_LockMutex(&rngMutex) != 0) {
        WOLFSSL_MSG("Unable to lock RNG mutex");
        (void)wc_UnLockMutex(&jobs_mutex);
        return;
    }
    if (wc_LockMutex(&crypto_mutex) != 0) {
        WOLFSSL_MSG("Unable to lock crypto mutex");
        (void)wc_UnLockMutex(&rngMutex);
        (void)wc_UnLockMutex(&jobs_mutex);
        return;
    }

    /* The RNG is seeded lazily and then kept, so a re-init would otherwise
     * leave one behind that was built under the previous configuration and
     * silently ignore a new heap or devId. */
    if (rngInit == 1) {
        if (wc_FreeRng(&rng) != 0) {
            WOLFSSL_MSG("Error free'ing the previous RNG");
        }
        rngInit = 0;
    }

    XMEMSET(&activeJobs, 0, MAX_JOBS * sizeof(Jobs));
    ForceZero(&keyStore, MAX_KEYSTORE * sizeof(Keys));

    if (config != NULL) {
        cryptoHeap  = config->heap;
        cryptoDevId = config->devId;
    }
    else {
        cryptoHeap  = NULL;
        cryptoDevId = WOLFSSL_AUTOSAR_DEVID;
    }

    if (wc_UnLockMutex(&crypto_mutex) != 0) {
        WOLFSSL_MSG("Unable to unlock crypto mutex");
    }
    if (wc_UnLockMutex(&rngMutex) != 0) {
        WOLFSSL_MSG("Unable to unlock RNG mutex");
    }
    if (wc_UnLockMutex(&jobs_mutex) != 0) {
        WOLFSSL_MSG("Unable to unlock jobs mutex");
    }
}


/* returns E_OK on success and E_NOT_OK on failure */
Std_ReturnType Crypto_KeyElementSet(uint32 keyId, uint32 eId, const uint8* key,
        uint32 keySz)
{
    Std_ReturnType ret = E_OK;

    if (key == NULL || keySz == 0 || keyId >= MAX_KEYSTORE) {
        WOLFSSL_MSG("Bad argument to Crypto_KeyElementSet");
        ret = E_NOT_OK;
    }

    if (ret == E_OK && wc_LockMutex(&crypto_mutex) != 0) {
        WOLFSSL_MSG("Unable to lock crypto mutex");
        ret = E_NOT_OK;
    }

    if (ret == E_OK) {
        if (keySz > sizeof(keyStore[keyId].v.key)) {
            ret =  E_NOT_OK;
        }
        if (ret == E_OK) {
            WOLFSSL_MSG("Setting new key");
            ForceZero(&keyStore[keyId].v, sizeof(keyStore[keyId].v));
            keyStore[keyId].eId     = eId;
            keyStore[keyId].refType = KEY_REF_RAW;
            XMEMCPY(keyStore[keyId].v.key, key, keySz);
            keyStore[keyId].keyLen  = keySz;
        }

        if (wc_UnLockMutex(&crypto_mutex) != 0) {
            WOLFSSL_MSG("Unable to unlock crypto mutex");
            ret = E_NOT_OK;
        }
    }

    return ret;
}


#ifdef WOLF_PRIVATE_KEY_ID
/* Points a keystore slot at a key that lives in a device, identified by an
 * opaque byte string the crypto callback understands. No key material is
 * stored, and none is needed: the driver initializes its AES contexts with
 * wc_AesInit_Id() so the key never enters RAM.
 *
 * returns E_OK on success and E_NOT_OK on failure */
Std_ReturnType Crypto_KeyElementSetId(uint32 keyId, uint32 eId,
        const uint8* id, uint32 idLen)
{
    Std_ReturnType ret = E_OK;

    if (id == NULL || idLen == 0 || keyId >= MAX_KEYSTORE) {
        WOLFSSL_MSG("Bad argument to Crypto_KeyElementSetId");
        ret = E_NOT_OK;
    }
    else if (idLen > sizeof(keyStore[keyId].v.id)) {
        WOLFSSL_MSG("Key identifier is too long for the slot (MAX_KEY_ID_LEN, "
                    "which cannot exceed AES_MAX_ID_LEN)");
        ret = E_NOT_OK;
    }

    if (ret == E_OK && wc_LockMutex(&crypto_mutex) != 0) {
        WOLFSSL_MSG("Unable to lock crypto mutex");
        ret = E_NOT_OK;
    }

    if (ret == E_OK) {
        WOLFSSL_MSG("Setting new device key identifier");
        ForceZero(&keyStore[keyId].v, sizeof(keyStore[keyId].v));
        keyStore[keyId].eId     = eId;
        keyStore[keyId].refType = KEY_REF_ID;
        XMEMCPY(keyStore[keyId].v.id, id, idLen);
        keyStore[keyId].keyLen  = idLen;

        if (wc_UnLockMutex(&crypto_mutex) != 0) {
            WOLFSSL_MSG("Unable to unlock crypto mutex");
            ret = E_NOT_OK;
        }
    }

    return ret;
}


/* As Crypto_KeyElementSetId() but with a printable label.
 *
 * returns E_OK on success and E_NOT_OK on failure */
Std_ReturnType Crypto_KeyElementSetLabel(uint32 keyId, uint32 eId,
        const char* label)
{
    Std_ReturnType ret = E_OK;
    word32 len = 0;

    if (label == NULL || keyId >= MAX_KEYSTORE) {
        WOLFSSL_MSG("Bad argument to Crypto_KeyElementSetLabel");
        ret = E_NOT_OK;
    }
    else {
        /* MAX_KEY_LABEL_LEN characters are allowed; the buffer is one longer
         * for the terminator, so the documented maximum fits. */
        len = (word32)XSTRLEN(label);
        if (len == 0 || len > MAX_KEY_LABEL_LEN) {
            WOLFSSL_MSG("Key label is empty or too long");
            ret = E_NOT_OK;
        }
    }

    if (ret == E_OK && wc_LockMutex(&crypto_mutex) != 0) {
        WOLFSSL_MSG("Unable to lock crypto mutex");
        ret = E_NOT_OK;
    }

    if (ret == E_OK) {
        WOLFSSL_MSG("Setting new device key label");
        ForceZero(&keyStore[keyId].v, sizeof(keyStore[keyId].v));
        keyStore[keyId].eId     = eId;
        keyStore[keyId].refType = KEY_REF_LABEL;
        XMEMCPY(keyStore[keyId].v.label, label, len);
        keyStore[keyId].v.label[len] = '\0';
        keyStore[keyId].keyLen  = len;

        if (wc_UnLockMutex(&crypto_mutex) != 0) {
            WOLFSSL_MSG("Unable to unlock crypto mutex");
            ret = E_NOT_OK;
        }
    }

    return ret;
}
#endif /* WOLF_PRIVATE_KEY_ID */
#endif /* NO_WOLFSSL_AUTOSAR_CRYPTO */
#endif /* WOLFSSL_AUTOSAR */

