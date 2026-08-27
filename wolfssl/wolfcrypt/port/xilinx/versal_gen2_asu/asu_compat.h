/* asu_compat.h
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

/* Names that moved between the Vitis 2025.2 and 2026.1 xilasu client APIs.
 * The rest of the port uses the WC_ASU_ names from here so the engine files
 * read the same against either release.
 *
 * Set WOLFSSL_VERSAL_GEN2_ASU_XILASU_2026_1 in user_settings.h for a 2026.1
 * BSP; asu_settings.h assumes 2025.2 otherwise.
 *
 * The xilasu names are only read here, never redefined: AMD is free to bring
 * an old spelling back, and a #define of theirs would then collide.
 */

#ifndef WOLFSSL_VERSAL_GEN2_ASU_COMPAT_H
#define WOLFSSL_VERSAL_GEN2_ASU_COMPAT_H

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_VERSAL_GEN2_ASU

#include <wolfssl/wolfcrypt/types.h> /* WC_INLINE */

/* Every header the names below come from, so this one stands on its own and
 * does not depend on what an engine file happened to include first. 2026.1
 * moved the operation flags into xasu_def.h; before that each engine carried
 * its own set. All five ship in both releases. */
#include "xasu_def.h"
#include "xasu_aesinfo.h"
#include "xasu_hmacinfo.h"
#include "xasu_shainfo.h"
#include "xasu_eccinfo.h"
#include "xasu_rsainfo.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Catch a BSP that does not match what the build was told to expect. Without
 * this the mismatch surfaces as a wall of undeclared-identifier errors from
 * whichever engine file happens to compile first. */
#if defined(WOLFSSL_VERSAL_GEN2_ASU_XILASU_2026_1) && !defined(XASU_INIT)
    #error "WOLFSSL_VERSAL_GEN2_ASU_XILASU_2026_1 named but the BSP xilasu \
predates 2026.1: name WOLFSSL_VERSAL_GEN2_ASU_XILASU_2025_2 instead"
#endif
#if defined(WOLFSSL_VERSAL_GEN2_ASU_XILASU_2025_2) && !defined(XASU_AES_INIT)
    #error "WOLFSSL_VERSAL_GEN2_ASU_XILASU_2025_2 named but the BSP xilasu \
looks newer than 2025.2: name WOLFSSL_VERSAL_GEN2_ASU_XILASU_2026_1 instead"
#endif

#ifdef WOLFSSL_VERSAL_GEN2_ASU_XILASU_2026_1

/* 2026.1 drives every engine from one set of operation flags. */
#define WC_ASU_AES_OP_INIT      XASU_INIT
#define WC_ASU_AES_OP_UPDATE    XASU_UPDATE
#define WC_ASU_AES_OP_FINAL     XASU_FINISH

#define WC_ASU_HMAC_OP_INIT     XASU_INIT
#define WC_ASU_HMAC_OP_UPDATE   XASU_UPDATE
#define WC_ASU_HMAC_OP_FINAL    XASU_FINISH

#define WC_ASU_SHA_OP_START     XASU_INIT
#define WC_ASU_SHA_OP_UPDATE    XASU_UPDATE
#define WC_ASU_SHA_OP_FINISH    XASU_FINISH

/* Curve sizes gained a private and a public form. The public one is twice the
 * private, and every use in the port is a curve length, so they all map to the
 * private form. The values themselves did not change. */
#define WC_ASU_ECC_P192_LEN     XASU_ECC_P192_PVT_KEY_SIZE_IN_BYTES
#define WC_ASU_ECC_P256_LEN     XASU_ECC_P256_PVT_KEY_SIZE_IN_BYTES
#define WC_ASU_ECC_P320_LEN     XASU_ECC_P320_PVT_KEY_SIZE_IN_BYTES
#define WC_ASU_ECC_P384_LEN     XASU_ECC_P384_PVT_KEY_SIZE_IN_BYTES
#define WC_ASU_ECC_P512_LEN     XASU_ECC_P512_PVT_KEY_SIZE_IN_BYTES
#define WC_ASU_ECC_P521_LEN     XASU_ECC_P521_PVT_KEY_SIZE_IN_BYTES

/* SHA-256 and SHAKE-256 share one length define now. Both are 32. */
#define WC_ASU_SHA_256_HASH_LEN XASU_SHA_SHAKE_256_HASH_LEN

/* The digest comes back by DMA, so the engine's own limit is the only one. */
#define WC_ASU_SHAKE_MAX_HASH_LEN XASU_SHAKE_256_MAX_HASH_LEN

#else /* Vitis 2025.2 */

#define WC_ASU_AES_OP_INIT      XASU_AES_INIT
#define WC_ASU_AES_OP_UPDATE    XASU_AES_UPDATE
#define WC_ASU_AES_OP_FINAL     XASU_AES_FINAL

#define WC_ASU_HMAC_OP_INIT     XASU_HMAC_INIT
#define WC_ASU_HMAC_OP_UPDATE   XASU_HMAC_UPDATE
#define WC_ASU_HMAC_OP_FINAL    XASU_HMAC_FINAL

#define WC_ASU_SHA_OP_START     XASU_SHA_START
#define WC_ASU_SHA_OP_UPDATE    XASU_SHA_UPDATE
#define WC_ASU_SHA_OP_FINISH    XASU_SHA_FINISH

#define WC_ASU_ECC_P192_LEN     XASU_ECC_P192_SIZE_IN_BYTES
#define WC_ASU_ECC_P256_LEN     XASU_ECC_P256_SIZE_IN_BYTES
#define WC_ASU_ECC_P320_LEN     XASU_ECC_P320_SIZE_IN_BYTES
#define WC_ASU_ECC_P384_LEN     XASU_ECC_P384_SIZE_IN_BYTES
#define WC_ASU_ECC_P512_LEN     XASU_ECC_P512_SIZE_IN_BYTES
#define WC_ASU_ECC_P521_LEN     XASU_ECC_P521_SIZE_IN_BYTES

#define WC_ASU_SHA_256_HASH_LEN XASU_SHA_256_HASH_LEN

/* The digest came back in the 64 byte mailbox response slot, so that is the
 * longest SHAKE the ASU could return however much the engine itself allows. */
#define WC_ASU_SHAKE_MAX_HASH_LEN 64

#endif /* WOLFSSL_VERSAL_GEN2_ASU_XILASU_2026_1 */

/* 2026.1 moved the HMAC key into a key object so it can name a key vault
 * entry instead. A zero KeyId keeps the key coming from KeyInAddr. */
static WC_INLINE void wc_AsuHmacSetKey(XAsu_HmacParams* p, const void* key,
    u32 keyLen)
{
#ifdef WOLFSSL_VERSAL_GEN2_ASU_XILASU_2026_1
    p->KeyObject.KeyInAddr = (u64)(UINTPTR)key;
    p->KeyObject.KeyInLen  = keyLen;
    p->KeyObject.KeyId     = 0U;
#else
    p->KeyAddr = (u64)(UINTPTR)key;
    p->KeyLen  = keyLen;
#endif
}

/* 2026.1 moved the ECC key into a key object so it can name a key vault entry
 * instead. KeyLen stays the curve length for both a private scalar and a public
 * point; the firmware knows a point is twice that. */
static WC_INLINE void wc_AsuEccSetKey(XAsu_EccParams* p, const void* key,
    u32 keyLen)
{
#ifdef WOLFSSL_VERSAL_GEN2_ASU_XILASU_2026_1
    p->Key.KeyAddr = (u64)(UINTPTR)key;
    p->Key.KeyLen  = keyLen;
    p->Key.KeyId   = 0U;
#else
    p->KeyAddr = (u64)(UINTPTR)key;
    p->KeyLen  = keyLen;
#endif
}

/* Same move for ECDH, which gains a key object per side. 2025.2 carried one
 * KeyLen for both keys, so the single length feeds both objects here. */
static WC_INLINE void wc_AsuEcdhSetKeys(XAsu_EcdhParams* p, const void* pvt,
    const void* pub, u32 keyLen)
{
#ifdef WOLFSSL_VERSAL_GEN2_ASU_XILASU_2026_1
    p->PvtKey.KeyAddr = (u64)(UINTPTR)pvt;
    p->PvtKey.KeyLen  = keyLen;
    p->PvtKey.KeyId   = 0U;
    p->PubKey.KeyAddr = (u64)(UINTPTR)pub;
    p->PubKey.KeyLen  = keyLen;
    p->PubKey.KeyId   = 0U;
#else
    p->PvtKeyAddr = (u64)(UINTPTR)pvt;
    p->PubKeyAddr = (u64)(UINTPTR)pub;
    p->KeyLen     = keyLen;
#endif
}

/* 2026.1 wants the size of the caller's output buffer up front, and somewhere
 * to report how much was produced. The client rejects the request when either
 * is missing, so both have to be set even though 2025.2 had neither. outLen
 * points at a 4-byte slot the mailbox response fills in.
 * Not a DMA target, so it takes no cache maintenance: the client CPU-copies
 * the value in, and invalidating the line would throw that write away. */
static WC_INLINE void wc_AsuRsaSetOutLen(XAsu_RsaParams* op, u32 bufSize,
    u32* outLen)
{
#ifdef WOLFSSL_VERSAL_GEN2_ASU_XILASU_2026_1
    op->OutputDataLen = bufSize;
    op->OutputLenAddr = (u64)(UINTPTR)outLen;
    op->KeyId         = 0U;
#else
    (void)op; (void)bufSize; (void)outLen;
#endif
}

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_VERSAL_GEN2_ASU */

#endif /* WOLFSSL_VERSAL_GEN2_ASU_COMPAT_H */
