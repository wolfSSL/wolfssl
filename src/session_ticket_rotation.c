/* session_ticket_rotation.c
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef HAVE_SESSION_TICKET

#include <wolfssl/session_ticket_rotation.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <string.h>

/* Get current time as unsigned long */
static unsigned long ticketRotation_GetTime(void)
{
    /* Use wolfSSL time abstraction */
    return (unsigned long)XTIME(NULL);
}

/* Derive a key from master secret using HKDF-like construction */
static int ticketRotation_DeriveKey(TicketKeyRotationCtx* ctx,
                                     unsigned long counter,
                                     TicketKeyEntry* entry)
{
    int ret;
    Hmac hmac;
    unsigned char prk[WC_SHA256_DIGEST_SIZE];
    unsigned char info[WOLFSSL_TICKET_HKDF_INFO_SIZE + sizeof(unsigned long)];
    unsigned char okm[WOLFSSL_TICKET_ENC_KEY_SIZE + WOLFSSL_TICKET_HMAC_KEY_SIZE
                      + WOLFSSL_TICKET_KEY_NAME_SIZE];
    int okmLen = (int)sizeof(okm);
    int infoLen;

    if (ctx == NULL || entry == NULL)
        return BAD_FUNC_ARG;

    if (ctx->masterSecretLen == 0)
        return BAD_FUNC_ARG;

    /* Step 1: Extract - HMAC-SHA256(salt=zeros, IKM=masterSecret) */
    ret = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
    if (ret != 0)
        return ret;

    ret = wc_HmacSetKey(&hmac, WC_SHA256, (const byte*)"", 0);
    if (ret != 0) {
        wc_HmacFree(&hmac);
        return ret;
    }

    ret = wc_HmacUpdate(&hmac, ctx->masterSecret, ctx->masterSecretLen);
    if (ret != 0) {
        wc_HmacFree(&hmac);
        return ret;
    }

    ret = wc_HmacFinal(&hmac, prk);
    wc_HmacFree(&hmac);
    if (ret != 0)
        return ret;

    /* Step 2: Expand - Build info = HKDF_INFO || counter */
    XMEMCPY(info, WOLFSSL_TICKET_HKDF_INFO, WOLFSSL_TICKET_HKDF_INFO_SIZE);
    XMEMCPY(info + WOLFSSL_TICKET_HKDF_INFO_SIZE, &counter, sizeof(counter));
    infoLen = WOLFSSL_TICKET_HKDF_INFO_SIZE + (int)sizeof(counter);

    /* Simple HKDF-Expand: T(1) || T(2) || ... */
    {
        int done = 0;
        int idx = 0;
        unsigned char T[WC_SHA256_DIGEST_SIZE];
        unsigned char prev[WC_SHA256_DIGEST_SIZE];
        int prevLen = 0;
        unsigned char ctr = 1;

        while (done < okmLen) {
            int copyLen;

            ret = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
            if (ret != 0) return ret;

            ret = wc_HmacSetKey(&hmac, WC_SHA256, prk, WC_SHA256_DIGEST_SIZE);
            if (ret != 0) { wc_HmacFree(&hmac); return ret; }

            if (prevLen > 0) {
                ret = wc_HmacUpdate(&hmac, prev, prevLen);
                if (ret != 0) { wc_HmacFree(&hmac); return ret; }
            }

            ret = wc_HmacUpdate(&hmac, (const byte*)info, infoLen);
            if (ret != 0) { wc_HmacFree(&hmac); return ret; }

            ret = wc_HmacUpdate(&hmac, &ctr, 1);
            if (ret != 0) { wc_HmacFree(&hmac); return ret; }

            ret = wc_HmacFinal(&hmac, T);
            wc_HmacFree(&hmac);
            if (ret != 0) return ret;

            copyLen = okmLen - done;
            if (copyLen > WC_SHA256_DIGEST_SIZE)
                copyLen = WC_SHA256_DIGEST_SIZE;

            XMEMCPY(okm + done, T, copyLen);
            done += copyLen;
            XMEMCPY(prev, T, WC_SHA256_DIGEST_SIZE);
            prevLen = WC_SHA256_DIGEST_SIZE;
            ctr++;
            idx++;

            if (idx > 10) {
                ret = BAD_STATE_E;
                break;
            }
        }
        if (ret != 0)
            return ret;
    }

    /* Split OKM into encKey, hmacKey, keyName */
    XMEMCPY(entry->encKey, okm, WOLFSSL_TICKET_ENC_KEY_SIZE);
    XMEMCPY(entry->hmacKey, okm + WOLFSSL_TICKET_ENC_KEY_SIZE,
             WOLFSSL_TICKET_HMAC_KEY_SIZE);
    XMEMCPY(entry->keyName,
             okm + WOLFSSL_TICKET_ENC_KEY_SIZE + WOLFSSL_TICKET_HMAC_KEY_SIZE,
             WOLFSSL_TICKET_KEY_NAME_SIZE);

    /* Clear sensitive temp data */
    ForceZero(prk, sizeof(prk));
    ForceZero(okm, sizeof(okm));

    return 0;
}

/* Internal rotate: must be called with lock held */
static int ticketRotation_RotateInternal(TicketKeyRotationCtx* ctx)
{
    int ret;
    int newIdx;
    unsigned long now;
    int i;

    now = ticketRotation_GetTime();

    /* Mark current active key as inactive */
    if (ctx->currentKeyIndex >= 0 &&
        ctx->currentKeyIndex < WOLFSSL_TICKET_KEY_TABLE_SIZE) {
        ctx->keys[ctx->currentKeyIndex].active = 0;
    }

    /* Find a free slot or the oldest slot */
    newIdx = -1;
    for (i = 0; i < WOLFSSL_TICKET_KEY_TABLE_SIZE; i++) {
        if (ctx->keys[i].createdAt == 0) {
            newIdx = i;
            break;
        }
    }

    /* If no free slot, evict the oldest expired key */
    if (newIdx < 0) {
        unsigned long oldest = now;
        int oldestIdx = 0;
        for (i = 0; i < WOLFSSL_TICKET_KEY_TABLE_SIZE; i++) {
            if (ctx->keys[i].createdAt < oldest) {
                oldest = ctx->keys[i].createdAt;
                oldestIdx = i;
            }
        }
        newIdx = oldestIdx;
    }

    /* Derive new key material */
    ctx->rotationCounter++;
    ret = ticketRotation_DeriveKey(ctx, ctx->rotationCounter,
                                   &ctx->keys[newIdx]);
    if (ret != 0)
        return ret;

    /* Set timestamps */
    ctx->keys[newIdx].createdAt = now;
    ctx->keys[newIdx].expiresAt = now + ctx->rotationInterval
                                      + ctx->gracePeriod;
    ctx->keys[newIdx].active = 1;

    ctx->currentKeyIndex = newIdx;
    if (ctx->keyCount < WOLFSSL_TICKET_KEY_TABLE_SIZE)
        ctx->keyCount++;

    /* Fire rotation callback if set */
    if (ctx->onRotation != NULL) {
        ctx->onRotation(ctx->rotationCbCtx,
                        ctx->keys[newIdx].keyName, newIdx);
    }

    return 0;
}

/* Initialize the ticket key rotation context */
int wolfSSL_TicketKeyRotation_Init(TicketKeyRotationCtx* ctx)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(ctx, 0, sizeof(TicketKeyRotationCtx));
    ctx->currentKeyIndex  = -1;
    ctx->rotationInterval = WOLFSSL_TICKET_KEY_ROTATION_DEFAULT_INTERVAL;
    ctx->gracePeriod      = WOLFSSL_TICKET_KEY_ROTATION_DEFAULT_INTERVAL / 2;
    ctx->rotationCounter  = 0;
    ctx->onRotation       = NULL;
    ctx->rotationCbCtx    = NULL;
    ctx->initialized      = 0;

#ifdef WOLFSSL_MUTEX
    if (wc_InitMutex(&ctx->lock) != 0)
        return BAD_MUTEX_E;
#endif

    ctx->initialized = 1;
    return 0;
}

/* Free resources */
void wolfSSL_TicketKeyRotation_Free(TicketKeyRotationCtx* ctx)
{
    if (ctx == NULL)
        return;

    /* Zeroize all key material */
    ForceZero(ctx->keys, sizeof(ctx->keys));
    ForceZero(ctx->masterSecret, sizeof(ctx->masterSecret));

#ifdef WOLFSSL_MUTEX
    if (ctx->initialized)
        wc_FreeMutex(&ctx->lock);
#endif

    ctx->initialized = 0;
}

/* Set master secret for HKDF derivation */
int wolfSSL_TicketKeyRotation_SetMasterSecret(TicketKeyRotationCtx* ctx,
                                               const unsigned char* secret,
                                               int secretLen)
{
    if (ctx == NULL || secret == NULL || secretLen <= 0)
        return BAD_FUNC_ARG;

    if (secretLen > (int)sizeof(ctx->masterSecret))
        secretLen = (int)sizeof(ctx->masterSecret);

    XMEMCPY(ctx->masterSecret, secret, secretLen);
    ctx->masterSecretLen = secretLen;
    return 0;
}

/* Set rotation interval */
int wolfSSL_TicketKeyRotation_SetInterval(TicketKeyRotationCtx* ctx,
                                           unsigned long intervalSec)
{
    if (ctx == NULL || intervalSec == 0)
        return BAD_FUNC_ARG;

    ctx->rotationInterval = intervalSec;
    return 0;
}

/* Set grace period for old key retention */
int wolfSSL_TicketKeyRotation_SetGracePeriod(TicketKeyRotationCtx* ctx,
                                              unsigned long graceSec)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    ctx->gracePeriod = graceSec;
    return 0;
}

/* Set rotation callback */
int wolfSSL_TicketKeyRotation_SetCallback(TicketKeyRotationCtx* ctx,
                                           TicketKeyRotationCb cb,
                                           void* userCtx)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    ctx->onRotation    = cb;
    ctx->rotationCbCtx = userCtx;
    return 0;
}

/* Check if rotation is needed and rotate */
int wolfSSL_TicketKeyRotation_CheckAndRotate(TicketKeyRotationCtx* ctx)
{
    int ret = 0;
    unsigned long now;

    if (ctx == NULL || !ctx->initialized)
        return BAD_FUNC_ARG;

#ifdef WOLFSSL_MUTEX
    if (wc_LockMutex(&ctx->lock) != 0)
        return BAD_MUTEX_E;
#endif

    now = ticketRotation_GetTime();

    /* Rotate if no active key or current key has expired */
    if (ctx->currentKeyIndex < 0 ||
        now >= ctx->keys[ctx->currentKeyIndex].createdAt
               + ctx->rotationInterval) {
        ret = ticketRotation_RotateInternal(ctx);
    }

#ifdef WOLFSSL_MUTEX
    wc_UnLockMutex(&ctx->lock);
#endif

    return ret;
}

/* Force immediate rotation */
int wolfSSL_TicketKeyRotation_ForceRotate(TicketKeyRotationCtx* ctx)
{
    int ret;

    if (ctx == NULL || !ctx->initialized)
        return BAD_FUNC_ARG;

#ifdef WOLFSSL_MUTEX
    if (wc_LockMutex(&ctx->lock) != 0)
        return BAD_MUTEX_E;
#endif

    ret = ticketRotation_RotateInternal(ctx);

#ifdef WOLFSSL_MUTEX
    wc_UnLockMutex(&ctx->lock);
#endif

    return ret;
}

/* Get the current active key */
int wolfSSL_TicketKeyRotation_GetActiveKey(TicketKeyRotationCtx* ctx,
                                            TicketKeyEntry** key)
{
    int ret = 0;

    if (ctx == NULL || key == NULL || !ctx->initialized)
        return BAD_FUNC_ARG;

#ifdef WOLFSSL_MUTEX
    if (wc_LockMutex(&ctx->lock) != 0)
        return BAD_MUTEX_E;
#endif

    if (ctx->currentKeyIndex >= 0 &&
        ctx->currentKeyIndex < WOLFSSL_TICKET_KEY_TABLE_SIZE &&
        ctx->keys[ctx->currentKeyIndex].active) {
        *key = &ctx->keys[ctx->currentKeyIndex];
    } else {
        *key = NULL;
        ret = BAD_STATE_E;
    }

#ifdef WOLFSSL_MUTEX
    wc_UnLockMutex(&ctx->lock);
#endif

    return ret;
}

/* Find key by name for decrypting incoming tickets */
int wolfSSL_TicketKeyRotation_FindKeyByName(TicketKeyRotationCtx* ctx,
                                             const unsigned char* name,
                                             TicketKeyEntry** key)
{
    int i;
    unsigned long now;

    if (ctx == NULL || name == NULL || key == NULL || !ctx->initialized)
        return BAD_FUNC_ARG;

#ifdef WOLFSSL_MUTEX
    if (wc_LockMutex(&ctx->lock) != 0)
        return BAD_MUTEX_E;
#endif

    *key = NULL;
    now = ticketRotation_GetTime();

    for (i = 0; i < WOLFSSL_TICKET_KEY_TABLE_SIZE; i++) {
        if (ctx->keys[i].createdAt == 0)
            continue;

        /* Check if key has fully expired (past grace period) */
        if (now > ctx->keys[i].expiresAt)
            continue;

        if (XMEMCMP(ctx->keys[i].keyName, name,
                     WOLFSSL_TICKET_KEY_NAME_SIZE) == 0) {
            *key = &ctx->keys[i];
            break;
        }
    }

#ifdef WOLFSSL_MUTEX
    wc_UnLockMutex(&ctx->lock);
#endif

    return (*key != NULL) ? 0 : WC_NO_ERR_TRACE(MATCH_SUITE_ERROR);
}

/* Get number of active keys in the table */
int wolfSSL_TicketKeyRotation_GetKeyCount(TicketKeyRotationCtx* ctx)
{
    int count = 0;
    int i;

    if (ctx == NULL || !ctx->initialized)
        return 0;

#ifdef WOLFSSL_MUTEX
    if (wc_LockMutex(&ctx->lock) != 0)
        return 0;
#endif

    for (i = 0; i < WOLFSSL_TICKET_KEY_TABLE_SIZE; i++) {
        if (ctx->keys[i].createdAt != 0)
            count++;
    }

#ifdef WOLFSSL_MUTEX
    wc_UnLockMutex(&ctx->lock);
#endif

    return count;
}

/* Purge expired keys from the table */
int wolfSSL_TicketKeyRotation_PurgeExpired(TicketKeyRotationCtx* ctx)
{
    int i;
    int purged = 0;
    unsigned long now;

    if (ctx == NULL || !ctx->initialized)
        return BAD_FUNC_ARG;

#ifdef WOLFSSL_MUTEX
    if (wc_LockMutex(&ctx->lock) != 0)
        return BAD_MUTEX_E;
#endif

    now = ticketRotation_GetTime();

    for (i = 0; i < WOLFSSL_TICKET_KEY_TABLE_SIZE; i++) {
        if (ctx->keys[i].createdAt == 0)
            continue;

        /* Don't purge the active key */
        if (i == ctx->currentKeyIndex && ctx->keys[i].active)
            continue;

        if (now > ctx->keys[i].expiresAt) {
            ForceZero(&ctx->keys[i], sizeof(TicketKeyEntry));
            ctx->keyCount--;
            purged++;
        }
    }

#ifdef WOLFSSL_MUTEX
    wc_UnLockMutex(&ctx->lock);
#endif

    return purged;
}

#endif /* HAVE_SESSION_TICKET */
