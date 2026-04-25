/* session_ticket_rotation.h
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

#ifndef WOLFSSL_SESSION_TICKET_ROTATION_H
#define WOLFSSL_SESSION_TICKET_ROTATION_H

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>

#ifdef HAVE_SESSION_TICKET

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum number of retained previous keys for in-flight connections */
#define WOLFSSL_TICKET_KEY_TABLE_SIZE   4
/* Default rotation interval in seconds (1 hour) */
#define WOLFSSL_TICKET_KEY_ROTATION_DEFAULT_INTERVAL  3600
/* Size of ticket encryption key in bytes */
#define WOLFSSL_TICKET_ENC_KEY_SIZE     32
/* Size of ticket HMAC key in bytes */
#define WOLFSSL_TICKET_HMAC_KEY_SIZE    32
/* Size of key name identifier */
#define WOLFSSL_TICKET_KEY_NAME_SIZE    16
/* HKDF info string for key derivation */
#define WOLFSSL_TICKET_HKDF_INFO        "wolfSSL ticket key"
#define WOLFSSL_TICKET_HKDF_INFO_SIZE   18

/* Callback type for rotation events */
typedef void (*TicketKeyRotationCb)(void* ctx, const unsigned char* keyName,
                                    int keyIndex);

/* Single ticket key entry */
typedef struct TicketKeyEntry {
    unsigned char  encKey[WOLFSSL_TICKET_ENC_KEY_SIZE];
    unsigned char  hmacKey[WOLFSSL_TICKET_HMAC_KEY_SIZE];
    unsigned char  keyName[WOLFSSL_TICKET_KEY_NAME_SIZE];
    unsigned long  createdAt;     /* Unix timestamp when key was created */
    unsigned long  expiresAt;     /* Unix timestamp when key expires */
    int            active;        /* 1 if this key is currently active */
} TicketKeyEntry;

/* Ticket key rotation context */
typedef struct TicketKeyRotationCtx {
    TicketKeyEntry    keys[WOLFSSL_TICKET_KEY_TABLE_SIZE];
    int               currentKeyIndex;
    int               keyCount;
    unsigned long     rotationInterval;   /* seconds between rotations */
    unsigned long     gracePeriod;        /* seconds to retain old keys */
    unsigned char     masterSecret[64];   /* master secret for HKDF */
    int               masterSecretLen;
    unsigned long     rotationCounter;    /* monotonic counter for derivation */
    TicketKeyRotationCb onRotation;
    void*             rotationCbCtx;
#ifdef WOLFSSL_MUTEX
    wolfSSL_Mutex     lock;
#endif
    int               initialized;
} TicketKeyRotationCtx;

/* Initialize the ticket key rotation context */
WOLFSSL_API int wolfSSL_TicketKeyRotation_Init(TicketKeyRotationCtx* ctx);

/* Free resources for the ticket key rotation context */
WOLFSSL_API void wolfSSL_TicketKeyRotation_Free(TicketKeyRotationCtx* ctx);

/* Set the master secret used for HKDF key derivation */
WOLFSSL_API int wolfSSL_TicketKeyRotation_SetMasterSecret(
    TicketKeyRotationCtx* ctx, const unsigned char* secret, int secretLen);

/* Set the rotation interval in seconds */
WOLFSSL_API int wolfSSL_TicketKeyRotation_SetInterval(
    TicketKeyRotationCtx* ctx, unsigned long intervalSec);

/* Set the grace period for retaining old keys */
WOLFSSL_API int wolfSSL_TicketKeyRotation_SetGracePeriod(
    TicketKeyRotationCtx* ctx, unsigned long graceSec);

/* Set the callback invoked on each key rotation */
WOLFSSL_API int wolfSSL_TicketKeyRotation_SetCallback(
    TicketKeyRotationCtx* ctx, TicketKeyRotationCb cb, void* userCtx);

/* Perform a key rotation if the current key has expired */
WOLFSSL_API int wolfSSL_TicketKeyRotation_CheckAndRotate(
    TicketKeyRotationCtx* ctx);

/* Force an immediate key rotation */
WOLFSSL_API int wolfSSL_TicketKeyRotation_ForceRotate(
    TicketKeyRotationCtx* ctx);

/* Retrieve the current active key for encrypting new tickets */
WOLFSSL_API int wolfSSL_TicketKeyRotation_GetActiveKey(
    TicketKeyRotationCtx* ctx, TicketKeyEntry** key);

/* Look up a key by its key name (for decrypting received tickets) */
WOLFSSL_API int wolfSSL_TicketKeyRotation_FindKeyByName(
    TicketKeyRotationCtx* ctx, const unsigned char* name, TicketKeyEntry** key);

/* Get the number of keys currently in the table */
WOLFSSL_API int wolfSSL_TicketKeyRotation_GetKeyCount(
    TicketKeyRotationCtx* ctx);

/* Purge all expired keys from the table */
WOLFSSL_API int wolfSSL_TicketKeyRotation_PurgeExpired(
    TicketKeyRotationCtx* ctx);

#ifdef __cplusplus
}
#endif

#endif /* HAVE_SESSION_TICKET */
#endif /* WOLFSSL_SESSION_TICKET_ROTATION_H */
