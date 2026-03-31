/* wc_she.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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

/*
 * SHE (Secure Hardware Extension) key update message generation.
 *
 * Software-only computation of M1/M2/M3 for CMD_LOAD_KEY and optional
 * M4/M5 verification.  Ported from the wolfHSM reference implementation
 * (src/wh_she_crypto.c) and adapted to wolfSSL conventions.
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#ifdef WOLFSSL_SHE

#ifdef NO_AES
    #error "SHE requires AES (NO_AES is defined)"
#endif
#ifndef HAVE_AES_CBC
    #error "SHE requires AES-CBC (HAVE_AES_CBC is not defined)"
#endif
#ifndef WOLFSSL_AES_DIRECT
    #error "SHE requires AES direct (WOLFSSL_AES_DIRECT is not defined)"
#endif
#ifndef WOLFSSL_CMAC
    #error "SHE requires CMAC (WOLFSSL_CMAC is not defined)"
#endif

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/cmac.h>
#include <wolfssl/wolfcrypt/wc_she.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#ifdef WOLF_CRYPTO_CB
    #include <wolfssl/wolfcrypt/cryptocb.h>
#endif

#ifdef WC_SHE_SW_DEFAULT
/* Software-only default UID for example usage only. Uses the SHE specification
 * test vector UID value. Override by defining WC_SHE_DEFAULT_UID before
 * including this file. */
#ifndef WC_SHE_DEFAULT_UID
#define WC_SHE_DEFAULT_UID { \
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 \
}
#endif
static const byte wc_She_DefaultUid[] = WC_SHE_DEFAULT_UID;

/* Software-only default counter start value for testing. Uses the SHE
 * specification test vector counter value. Override by defining
 * WC_SHE_DEFAULT_COUNTER before including this file. */
#ifndef WC_SHE_DEFAULT_COUNTER
#define WC_SHE_DEFAULT_COUNTER 1
#endif
#endif /* WC_SHE_SW_DEFAULT */

/* -------------------------------------------------------------------------- */
/* Miyaguchi-Preneel AES-128 compression (internal)                           */
/*                                                                            */
/* H_0 = 0                                                                    */
/* H_i = E_{H_{i-1}}(M_i)  XOR  M_i  XOR  H_{i-1}                          */
/*                                                                            */
/* Only valid for AES-128 where key size == block size.                       */
/*                                                                            */
/* Ported from wolfHSM wh_She_AesMp16_ex() in src/wh_she_crypto.c.           */
/* The caller (GenerateM1M2M3 / GenerateM4M5) owns the Aes object.            */
/* -------------------------------------------------------------------------- */
int wc_SHE_AesMp16(Aes* aes, const byte* in, word32 inSz, byte* out)
{
    int ret;
    int i = 0;
    int j;
    byte paddedInput[AES_BLOCK_SIZE];
    byte prev[WC_SHE_KEY_SZ] = {0};

    if (aes == NULL || in == NULL || inSz == 0 || out == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Set initial key = H_0 = all zeros */
    ret = wc_AesSetKeyDirect(aes, prev, AES_BLOCK_SIZE, NULL,
                             AES_ENCRYPTION);

    while (ret == 0 && i < (int)inSz) {
        /* Copy next input block, zero-padding if short */
        if ((int)inSz - i < (int)AES_BLOCK_SIZE) {
            XMEMCPY(paddedInput, in + i, inSz - i);
            XMEMSET(paddedInput + (inSz - i), 0,
                     AES_BLOCK_SIZE - (inSz - i));
        }
        else {
            XMEMCPY(paddedInput, in + i, AES_BLOCK_SIZE);
        }

        /* E_{H_{i-1}}(M_i) */
        ret = wc_AesEncryptDirect(aes, out, paddedInput);

        if (ret == 0) {
            /* H_i = E_{H_{i-1}}(M_i) XOR M_i XOR H_{i-1} */
            for (j = 0; j < (int)AES_BLOCK_SIZE; j++) {
                out[j] ^= paddedInput[j];
                out[j] ^= prev[j];
            }

            /* Save H_i as the previous output */
            XMEMCPY(prev, out, AES_BLOCK_SIZE);

            /* Set key = H_i for next block */
            ret = wc_AesSetKeyDirect(aes, out, AES_BLOCK_SIZE,
                                     NULL, AES_ENCRYPTION);

            i += AES_BLOCK_SIZE;
        }
    }

    return ret;
}

/* -------------------------------------------------------------------------- */
/* Context init                                                               */
/*                                                                            */
/* Zero-initialize the SHE context and store the heap hint and device ID      */
/* for use by subsequent crypto operations.                                   */
/* -------------------------------------------------------------------------- */
int wc_SHE_Init(wc_SHE* she, void* heap, int devId)
{
    if (she == NULL) {
        return BAD_FUNC_ARG;
    }

    ForceZero(she, sizeof(wc_SHE));
    she->heap  = heap;
    she->devId = devId;

    return 0;
}

#ifdef WOLF_PRIVATE_KEY_ID
/* -------------------------------------------------------------------------- */
/* Context init with opaque hardware key identifier                           */
/*                                                                            */
/* Like wc_SHE_Init but also stores an opaque byte-string key ID that        */
/* crypto callback backends can use to look up the authorizing key in         */
/* hardware (e.g. an HSM slot reference or PKCS#11 object handle).           */
/* -------------------------------------------------------------------------- */
int wc_SHE_Init_Id(wc_SHE* she, unsigned char* id, int len,
                    void* heap, int devId)
{
    int ret;

    if (she == NULL || id == NULL) {
        return BAD_FUNC_ARG;
    }

    if (len < 0 || len > WC_SHE_MAX_ID_LEN) {
        return BUFFER_E;
    }

    ret = wc_SHE_Init(she, heap, devId);
    if (ret != 0) {
        return ret;
    }

    XMEMCPY(she->id, id, (size_t)len);
    she->idLen    = len;
    she->labelLen = 0;

    return 0;
}

/* -------------------------------------------------------------------------- */
/* Context init with human-readable key label                                 */
/*                                                                            */
/* Like wc_SHE_Init but also stores a NUL-terminated string label that       */
/* crypto callback backends can use for string-based key lookup.             */
/* -------------------------------------------------------------------------- */
int wc_SHE_Init_Label(wc_SHE* she, const char* label,
                       void* heap, int devId)
{
    int    ret;
    size_t labelLen;

    if (she == NULL || label == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = wc_SHE_Init(she, heap, devId);
    if (ret != 0) {
        return ret;
    }

    labelLen = XSTRLEN(label);
    if (labelLen == 0 || labelLen > WC_SHE_MAX_LABEL_LEN) {
        return BUFFER_E;
    }

    XMEMCPY(she->label, label, labelLen);
    she->labelLen = (int)labelLen;
    she->idLen    = 0;

    return 0;
}
#endif /* WOLF_PRIVATE_KEY_ID */

/* -------------------------------------------------------------------------- */
/* Context free                                                               */
/*                                                                            */
/* Scrub all key material and reset the SHE context to zero.                  */
/* Safe to call on a NULL or already-freed context.                           */
/* -------------------------------------------------------------------------- */
void wc_SHE_Free(wc_SHE* she)
{
    if (she == NULL) {
        return;
    }

#if defined(WOLF_CRYPTO_CB) && defined(WOLF_CRYPTO_CB_FREE)
    if (she->devId != INVALID_DEVID) {
        int ret = wc_CryptoCb_Free(she->devId, WC_ALGO_TYPE_SHE,
                                   0, 0, she);
        if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE)) {
            return;
        }
        /* fall-through when unavailable */
    }
#endif /* WOLF_CRYPTO_CB && WOLF_CRYPTO_CB_FREE */

    ForceZero(she, sizeof(wc_SHE));
}

/* -------------------------------------------------------------------------- */
/* GetUID                                                                      */
/*                                                                            */
/* When a crypto callback is registered, it can be used to get the UID from  */
/* hardware. The caller can pass a challenge or other context via the void    */
/* ctx parameter (e.g. challenge buffer, HSM handle).                        */
/* Returns CRYPTOCB_UNAVAILABLE if no callback.                              */
/* -------------------------------------------------------------------------- */
#if defined(WOLF_CRYPTO_CB) && !defined(NO_WC_SHE_GETUID)
int wc_SHE_GetUID(wc_SHE* she, byte* uid, word32 uidSz,
                   const void* ctx)
{
    int ret;

    if (she == NULL || uid == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = wc_CryptoCb_SheGetUid(she, uid, uidSz, ctx);
    if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE)) {
        return ret;
    }

#ifdef WC_SHE_SW_DEFAULT
    /* Software-only default UID for example usage only. */
    if (uidSz < sizeof(wc_She_DefaultUid)) {
        return BUFFER_E;
    }
    XMEMCPY(uid, wc_She_DefaultUid, sizeof(wc_She_DefaultUid));
    ret = 0;
#endif

    return ret;
}
#endif /* WOLF_CRYPTO_CB && !NO_WC_SHE_GETUID */

/* -------------------------------------------------------------------------- */
/* GetCounter                                                                  */
/*                                                                            */
/* When a crypto callback is registered, it can be used to read the          */
/* monotonic counter from hardware. The caller can pass operational context   */
/* via the void ctx parameter (e.g. read counter/increment, read only).      */
/* Returns CRYPTOCB_UNAVAILABLE if no callback.                              */
/* -------------------------------------------------------------------------- */
#if defined(WOLF_CRYPTO_CB) && !defined(NO_WC_SHE_GETCOUNTER)
int wc_SHE_GetCounter(wc_SHE* she, word32* counter, const void* ctx)
{
    int ret;
#ifdef WC_SHE_SW_DEFAULT
    /* Software-only default counter for example usage only.
     * Simple static counter that increments on each call. */
    static word32 she_sw_counter = WC_SHE_DEFAULT_COUNTER;
#endif

    if (she == NULL || counter == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = wc_CryptoCb_SheGetCounter(she, counter, ctx);
    if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE)) {
        return ret;
    }

#ifdef WC_SHE_SW_DEFAULT
    *counter = she_sw_counter++;
    ret = 0;
#endif

    return ret;
}
#endif /* WOLF_CRYPTO_CB && !NO_WC_SHE_GETCOUNTER */

/* -------------------------------------------------------------------------- */
/* Extended SHE overrides                                                     */
/* -------------------------------------------------------------------------- */
#ifdef WOLFSSL_SHE_EXTENDED

int wc_SHE_SetKdfConstants(wc_SHE* she,
                            const byte* encC, word32 encCSz,
                            const byte* macC, word32 macCSz)
{
    if (she == NULL) {
        return BAD_FUNC_ARG;
    }

    if (encC != NULL) {
        if (encCSz != WC_SHE_KEY_SZ) {
            return BAD_FUNC_ARG;
        }
        XMEMCPY(she->kdfEncC, encC, WC_SHE_KEY_SZ);
        she->kdfEncOverride = 1;
    }

    if (macC != NULL) {
        if (macCSz != WC_SHE_KEY_SZ) {
            return BAD_FUNC_ARG;
        }
        XMEMCPY(she->kdfMacC, macC, WC_SHE_KEY_SZ);
        she->kdfMacOverride = 1;
    }

    return 0;
}

#endif /* WOLFSSL_SHE_EXTENDED */

/* -------------------------------------------------------------------------- */
/* GetUID                                                                     */

#if defined(WOLF_CRYPTO_CB) || !defined(NO_WC_SHE_IMPORT_M123)
/* -------------------------------------------------------------------------- */
/* Import M1/M2/M3                                                            */
/*                                                                            */
/* Copy externally-provided M1/M2/M3 into context and set generated flag.    */
/* -------------------------------------------------------------------------- */
int wc_SHE_ImportM1M2M3(wc_SHE* she,
                          const byte* m1, word32 m1Sz,
                          const byte* m2, word32 m2Sz,
                          const byte* m3, word32 m3Sz)
{
    if (she == NULL || m1 == NULL || m2 == NULL || m3 == NULL) {
        return BAD_FUNC_ARG;
    }
    if (m1Sz != WC_SHE_M1_SZ || m2Sz != WC_SHE_M2_SZ ||
        m3Sz != WC_SHE_M3_SZ) {
        return BAD_FUNC_ARG;
    }

    XMEMCPY(she->m1, m1, WC_SHE_M1_SZ);
    XMEMCPY(she->m2, m2, WC_SHE_M2_SZ);
    XMEMCPY(she->m3, m3, WC_SHE_M3_SZ);
    she->generated = 1;
    return 0;
}
#endif /* WOLF_CRYPTO_CB || !NO_WC_SHE_IMPORT_M123 */

/* -------------------------------------------------------------------------- */
/* Portable big-endian 32-bit store                                           */
/* -------------------------------------------------------------------------- */
static WC_INLINE void she_store_be32(byte* dst, word32 val)
{
    dst[0] = (byte)(val >> 24);
    dst[1] = (byte)(val >> 16);
    dst[2] = (byte)(val >>  8);
    dst[3] = (byte)(val);
}

/* Build M2P and M4P headers from counter and flags using standard SHE packing.
 * M2P header: counter(28b) | flags(4b) | zeros(96b) = 16 bytes
 * M4P header: counter(28b) | 1(1b) | zeros(99b) = 16 bytes
 * Writes to caller-provided buffers. Skipped if WOLFSSL_SHE_EXTENDED
 * override is active on the context. */
static void she_build_headers(wc_SHE* she, word32 counter, byte flags,
                               byte* m2pHeader, byte* m4pHeader)
{
    word32 field;

#ifdef WOLFSSL_SHE_EXTENDED
    if (she->m2pOverride) {
        XMEMCPY(m2pHeader, she->m2pHeader, WC_SHE_KEY_SZ);
    }
    else
#endif
    {
        XMEMSET(m2pHeader, 0, WC_SHE_KEY_SZ);
        field = (counter << WC_SHE_M2_COUNT_SHIFT) |
                (flags   << WC_SHE_M2_FLAGS_SHIFT);
        she_store_be32(m2pHeader, field);
    }

#ifdef WOLFSSL_SHE_EXTENDED
    if (she->m4pOverride) {
        XMEMCPY(m4pHeader, she->m4pHeader, WC_SHE_KEY_SZ);
    }
    else
#endif
    {
        XMEMSET(m4pHeader, 0, WC_SHE_KEY_SZ);
        field = (counter << WC_SHE_M4_COUNT_SHIFT) | WC_SHE_M4_COUNT_PAD;
        she_store_be32(m4pHeader, field);
    }

    (void)she;
}

#ifdef WOLFSSL_SHE_EXTENDED
int wc_SHE_SetM2Header(wc_SHE* she, const byte* header, word32 headerSz)
{
    if (she == NULL || header == NULL || headerSz != WC_SHE_KEY_SZ) {
        return BAD_FUNC_ARG;
    }

    XMEMCPY(she->m2pHeader, header, WC_SHE_KEY_SZ);
    she->m2pOverride = 1;
    return 0;
}

int wc_SHE_SetM4Header(wc_SHE* she, const byte* header, word32 headerSz)
{
    if (she == NULL || header == NULL || headerSz != WC_SHE_KEY_SZ) {
        return BAD_FUNC_ARG;
    }

    XMEMCPY(she->m4pHeader, header, WC_SHE_KEY_SZ);
    she->m4pOverride = 1;
    return 0;
}
#endif /* WOLFSSL_SHE_EXTENDED */

/* -------------------------------------------------------------------------- */
/* M1/M2/M3 generation                                                       */
/*                                                                            */
/* Derives K1 and K2 from AuthKey via Miyaguchi-Preneel, then builds:        */
/*   M1 = UID | TargetKeyID | AuthKeyID                                      */
/*   M2 = AES-CBC(K1, IV=0, counter|flags|pad|newkey)                        */
/*   M3 = AES-CMAC(K2, M1 | M2)                                             */
/*                                                                            */
/* When a crypto callback is registered and the SHE context has a valid      */
/* device ID, the callback is tried first. This is useful when a secure      */
/* element or HSM holds the auth key internally and can generate M1/M2/M3    */
/* directly. If the callback returns CRYPTOCB_UNAVAILABLE, the software      */
/* path runs.                                                                */
/*                                                                            */
/* Ported from wolfHSM wh_She_GenerateLoadableKey() in wh_she_crypto.c.      */
/* -------------------------------------------------------------------------- */
int wc_SHE_GenerateM1M2M3(wc_SHE* she,
                      const byte* uid, word32 uidSz,
                      byte authKeyId, const byte* authKey, word32 authKeySz,
                      byte targetKeyId, const byte* newKey, word32 newKeySz,
                      word32 counter, byte flags,
                      byte* m1, word32 m1Sz,
                      byte* m2, word32 m2Sz,
                      byte* m3, word32 m3Sz)
{
    int    ret = 0;
    byte   m2pHeader[WC_SHE_KEY_SZ];
    byte   m4pHeader[WC_SHE_KEY_SZ];
    byte   k1[WC_SHE_KEY_SZ];
    byte   k2[WC_SHE_KEY_SZ];
    byte   kdfInput[WC_SHE_KEY_SZ * 2];
    byte   encC[] = WC_SHE_KEY_UPDATE_ENC_C;
    byte   macC[] = WC_SHE_KEY_UPDATE_MAC_C;
    word32 cmacSz = AES_BLOCK_SIZE;
    WC_DECLARE_VAR(aes, Aes, 1, 0);
    WC_DECLARE_VAR(cmac, Cmac, 1, 0);

    /* Validate SHE context first -- required for both callback and software */
    if (she == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLF_CRYPTO_CB
    /* Try callback first -- callback handles its own parameter validation.
     * This allows callers to pass NULL authKey/newKey when a secure element
     * holds the keys and the callback talks to it directly. */
    if (she->devId != INVALID_DEVID) {
        ret = wc_CryptoCb_SheGenerateM1M2M3(she, uid, uidSz,
                  authKeyId, authKey, authKeySz,
                  targetKeyId, newKey, newKeySz,
                  counter, flags,
                  m1, m1Sz, m2, m2Sz, m3, m3Sz);
        if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE)) {
            return ret;
        }
        /* fall-through to software path */
        ret = 0;
    }
#endif

    /* Software path -- validate all parameters */
    if (uid == NULL || uidSz != WC_SHE_UID_SZ ||
        authKey == NULL || authKeySz != WC_SHE_KEY_SZ ||
        newKey == NULL || newKeySz != WC_SHE_KEY_SZ ||
        m1 == NULL || m1Sz < WC_SHE_M1_SZ ||
        m2 == NULL || m2Sz < WC_SHE_M2_SZ ||
        m3 == NULL || m3Sz < WC_SHE_M3_SZ) {
        return BAD_FUNC_ARG;
    }

    /* Override KDF constants if explicitly set */
#ifdef WOLFSSL_SHE_EXTENDED
    if (she->kdfEncOverride) {
        XMEMCPY(encC, she->kdfEncC, WC_SHE_KEY_SZ);
    }
    if (she->kdfMacOverride) {
        XMEMCPY(macC, she->kdfMacC, WC_SHE_KEY_SZ);
    }
#endif

    /* Build M2P/M4P headers from counter/flags (skipped if overridden) */
    she_build_headers(she, counter, flags, m2pHeader, m4pHeader);

    WC_ALLOC_VAR(aes, Aes, 1, she->heap);
    if (!WC_VAR_OK(aes)) {
        return MEMORY_E;
    }

    WC_ALLOC_VAR(cmac, Cmac, 1, she->heap);
    if (!WC_VAR_OK(cmac)) {
        WC_FREE_VAR(aes, she->heap);
        return MEMORY_E;
    }

    /* Init AES once -- used by both MP16 and CBC */
    ret = wc_AesInit(aes, she->heap, she->devId);
    if (ret != 0) {
        WC_FREE_VAR(aes, she->heap);
        WC_FREE_VAR(cmac, she->heap);
        return ret;
    }

    /* ---- Derive K1 = AES-MP(AuthKey || CENC) ---- */
    XMEMCPY(kdfInput, authKey, WC_SHE_KEY_SZ);
    XMEMCPY(kdfInput + WC_SHE_KEY_SZ, encC, WC_SHE_KEY_SZ);
    ret = wc_SHE_AesMp16(aes, kdfInput, WC_SHE_KEY_SZ * 2, k1);

    /* ---- Build M1: UID(15B) | TargetKeyID(4b) | AuthKeyID(4b) ---- */
    if (ret == 0) {
        XMEMCPY(m1, uid, WC_SHE_UID_SZ);
        m1[WC_SHE_M1_KID_OFFSET] =
            (byte)((targetKeyId << WC_SHE_M1_KID_SHIFT) |
                   (authKeyId   << WC_SHE_M1_AID_SHIFT));
    }

    /* ---- Build cleartext M2 and encrypt with K1 ---- */
    if (ret == 0) {
        /* M2P = m2pHeader(16B) | newKey(16B) */
        XMEMCPY(m2, m2pHeader, WC_SHE_KEY_SZ);
        XMEMCPY(m2 + WC_SHE_M2_KEY_OFFSET, newKey, WC_SHE_KEY_SZ);

        /* Encrypt M2 in-place with AES-128-CBC, IV = 0 */
        ret = wc_AesSetKey(aes, k1, WC_SHE_KEY_SZ, NULL, AES_ENCRYPTION);
        if (ret == 0) {
            ret = wc_AesCbcEncrypt(aes, m2, m2, WC_SHE_M2_SZ);
        }
    }

    /* ---- Derive K2 = AES-MP(AuthKey || CMAC_C) ---- */
    if (ret == 0) {
        XMEMCPY(kdfInput + WC_SHE_KEY_SZ, macC, WC_SHE_KEY_SZ);
        ret = wc_SHE_AesMp16(aes, kdfInput, WC_SHE_KEY_SZ * 2, k2);
    }

    /* ---- Build M3 = AES-CMAC(K2, M1 || M2) ---- */
    if (ret == 0) {
        ret = wc_InitCmac_ex(cmac, k2, WC_SHE_KEY_SZ, WC_CMAC_AES,
                              NULL, she->heap, she->devId);
    }
    if (ret == 0) {
        ret = wc_CmacUpdate(cmac, m1, WC_SHE_M1_SZ);
    }
    if (ret == 0) {
        ret = wc_CmacUpdate(cmac, m2, WC_SHE_M2_SZ);
    }
    if (ret == 0) {
        cmacSz = AES_BLOCK_SIZE;
        ret = wc_CmacFinal(cmac, m3, &cmacSz);
    }

    /* Scrub temporary key material */
    ForceZero(k1, sizeof(k1));
    ForceZero(k2, sizeof(k2));
    ForceZero(kdfInput, sizeof(kdfInput));

    wc_AesFree(aes);
    WC_FREE_VAR(aes, she->heap);
    WC_FREE_VAR(cmac, she->heap);
    return ret;
}

/* -------------------------------------------------------------------------- */
/* M4/M5 verification computation                                            */
/*                                                                            */
/* Derives K3 and K4 from NewKey via Miyaguchi-Preneel, then builds:         */
/*   M4 = UID | KeyID | AuthID | AES-ECB(K3, counter|pad)                   */
/*   M5 = AES-CMAC(K4, M4)                                                  */
/*                                                                            */
/* These are the expected proof messages that SHE hardware should return.     */
/*                                                                            */
/* When a crypto callback is registered and the SHE context has a valid      */
/* device ID, the callback is tried first. This is useful for uploading      */
/* M1/M2/M3 to an HSM which loads the key and returns M4/M5 as proof.       */
/* If the callback returns CRYPTOCB_UNAVAILABLE, the software path runs.     */
/* -------------------------------------------------------------------------- */
int wc_SHE_GenerateM4M5(wc_SHE* she,
                      const byte* uid, word32 uidSz,
                      byte authKeyId, byte targetKeyId,
                      const byte* newKey, word32 newKeySz,
                      word32 counter,
                      byte* m4, word32 m4Sz,
                      byte* m5, word32 m5Sz)
{
    int    ret = 0;
    byte   m2pHeader[WC_SHE_KEY_SZ];
    byte   m4pHeader[WC_SHE_KEY_SZ];
    byte   k3[WC_SHE_KEY_SZ];
    byte   k4[WC_SHE_KEY_SZ];
    byte   kdfInput[WC_SHE_KEY_SZ * 2];
    byte   encC[] = WC_SHE_KEY_UPDATE_ENC_C;
    byte   macC[] = WC_SHE_KEY_UPDATE_MAC_C;
    word32 cmacSz;
    WC_DECLARE_VAR(aes, Aes, 1, 0);
    WC_DECLARE_VAR(cmac, Cmac, 1, 0);

    /* Validate SHE context first */
    if (she == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLF_CRYPTO_CB
    /* Try callback first -- useful for uploading M1/M2/M3 to an HSM which
     * loads the key and returns the correct M4/M5 proof values.  The callback
     * handles its own parameter validation. */
    if (she->devId != INVALID_DEVID) {
        ret = wc_CryptoCb_SheGenerateM4M5(she, uid, uidSz,
                  authKeyId, targetKeyId,
                  newKey, newKeySz, counter,
                  m4, m4Sz, m5, m5Sz);
        if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE)) {
            return ret;
        }
        /* fall-through to software path */
        ret = 0;
    }
#endif

    /* Software path -- validate all parameters */
    if (uid == NULL || uidSz != WC_SHE_UID_SZ ||
        newKey == NULL || newKeySz != WC_SHE_KEY_SZ ||
        m4 == NULL || m4Sz < WC_SHE_M4_SZ ||
        m5 == NULL || m5Sz < WC_SHE_M5_SZ) {
        return BAD_FUNC_ARG;
    }

    /* Override KDF constants if explicitly set */
#ifdef WOLFSSL_SHE_EXTENDED
    if (she->kdfEncOverride) {
        XMEMCPY(encC, she->kdfEncC, WC_SHE_KEY_SZ);
    }
    if (she->kdfMacOverride) {
        XMEMCPY(macC, she->kdfMacC, WC_SHE_KEY_SZ);
    }
#endif

    /* Build headers from counter (skipped if overridden) */
    she_build_headers(she, counter, 0, m2pHeader, m4pHeader);

    WC_ALLOC_VAR(aes, Aes, 1, she->heap);
    if (!WC_VAR_OK(aes)) {
        return MEMORY_E;
    }

    WC_ALLOC_VAR(cmac, Cmac, 1, she->heap);
    if (!WC_VAR_OK(cmac)) {
        WC_FREE_VAR(aes, she->heap);
        return MEMORY_E;
    }

    /* Init AES once -- used by both MP16 and ECB */
    ret = wc_AesInit(aes, she->heap, she->devId);
    if (ret != 0) {
        WC_FREE_VAR(aes, she->heap);
        WC_FREE_VAR(cmac, she->heap);
        return ret;
    }

    /* ---- Derive K3 = AES-MP(NewKey || CENC) ---- */
    XMEMCPY(kdfInput, newKey, WC_SHE_KEY_SZ);
    XMEMCPY(kdfInput + WC_SHE_KEY_SZ, encC, WC_SHE_KEY_SZ);
    ret = wc_SHE_AesMp16(aes, kdfInput, WC_SHE_KEY_SZ * 2, k3);

    /* ---- Build M4: UID|IDs header + AES-ECB(K3, m4pHeader) ---- */
    if (ret == 0) {
        XMEMSET(m4, 0, WC_SHE_M4_SZ);

        XMEMCPY(m4, uid, WC_SHE_UID_SZ);
        m4[WC_SHE_M4_KID_OFFSET] =
            (byte)((targetKeyId << WC_SHE_M4_KID_SHIFT) |
                   (authKeyId   << WC_SHE_M4_AID_SHIFT));

        /* Copy pre-built M4P header (counter|pad) into M4 counter block */
        XMEMCPY(m4 + WC_SHE_M4_COUNT_OFFSET, m4pHeader,
                 WC_SHE_KEY_SZ);

        /* Encrypt the 16-byte counter block in-place with AES-ECB */
        ret = wc_AesSetKey(aes, k3, WC_SHE_KEY_SZ, NULL, AES_ENCRYPTION);
        if (ret == 0) {
            ret = wc_AesEncryptDirect(aes,
                    m4 + WC_SHE_M4_COUNT_OFFSET,
                    m4 + WC_SHE_M4_COUNT_OFFSET);
        }
    }

    /* ---- Derive K4 = AES-MP(NewKey || CMAC_C) ---- */
    if (ret == 0) {
        XMEMCPY(kdfInput + WC_SHE_KEY_SZ, macC, WC_SHE_KEY_SZ);
        ret = wc_SHE_AesMp16(aes, kdfInput, WC_SHE_KEY_SZ * 2, k4);
    }

    /* ---- Build M5 = AES-CMAC(K4, M4) ---- */
    if (ret == 0) {
        cmacSz = AES_BLOCK_SIZE;
        ret = wc_AesCmacGenerate_ex(cmac, m5, &cmacSz,
                m4, WC_SHE_M4_SZ, k4, WC_SHE_KEY_SZ,
                she->heap, she->devId);
    }

    ForceZero(k3, sizeof(k3));
    ForceZero(k4, sizeof(k4));
    ForceZero(kdfInput, sizeof(kdfInput));

    wc_AesFree(aes);
    WC_FREE_VAR(aes, she->heap);
    WC_FREE_VAR(cmac, she->heap);
    return ret;
}

/* -------------------------------------------------------------------------- */
/* One-shot Load Key helpers                                                   */
/*                                                                            */
/* Internal helper that does the actual work: imports M1/M2/M3 into the       */
/* already-initialized SHE context, calls GenerateM4M5 (which dispatches to   */
/* the crypto callback to send M1/M2/M3 to the HSM and receive M4/M5 back),  */
/* and frees the context.                                                      */
/* -------------------------------------------------------------------------- */
#ifndef NO_WC_SHE_LOADKEY
#if defined(WOLF_CRYPTO_CB) || !defined(NO_WC_SHE_IMPORT_M123)
static int wc_SHE_LoadKey_Internal(wc_SHE* she,
    const byte* m1, word32 m1Sz,
    const byte* m2, word32 m2Sz,
    const byte* m3, word32 m3Sz,
    byte* m4, word32 m4Sz,
    byte* m5, word32 m5Sz)
{
    int ret;

    ret = wc_SHE_ImportM1M2M3(she, m1, m1Sz, m2, m2Sz, m3, m3Sz);
    if (ret != 0) {
        wc_SHE_Free(she);
        return ret;
    }

    /* GenerateM4M5 with NULL uid/newKey -- the callback reads M1/M2/M3
     * from the context and sends them to the HSM which returns M4/M5. */
    ret = wc_SHE_GenerateM4M5(she, NULL, 0, 0, 0, NULL, 0, 0,
                               m4, m4Sz, m5, m5Sz);

    wc_SHE_Free(she);
    return ret;
}

/* -------------------------------------------------------------------------- */
/* wc_SHE_LoadKey                                                              */
/*                                                                            */
/* One-shot: Init, ImportM1M2M3, GenerateM4M5 (via callback), Free.           */
/* Requires a valid devId (not INVALID_DEVID) since the operation dispatches   */
/* to a hardware crypto callback.                                              */
/* -------------------------------------------------------------------------- */
int wc_SHE_LoadKey(
    void* heap, int devId,
    const byte* m1, word32 m1Sz,
    const byte* m2, word32 m2Sz,
    const byte* m3, word32 m3Sz,
    byte* m4, word32 m4Sz,
    byte* m5, word32 m5Sz)
{
    int ret;
    WC_DECLARE_VAR(she, wc_SHE, 1, heap);

    if (m1 == NULL || m2 == NULL || m3 == NULL ||
        m4 == NULL || m5 == NULL) {
        return BAD_FUNC_ARG;
    }

    if (devId == INVALID_DEVID) {
        return BAD_FUNC_ARG;
    }

    if (m1Sz != WC_SHE_M1_SZ || m2Sz != WC_SHE_M2_SZ ||
        m3Sz != WC_SHE_M3_SZ) {
        return BAD_FUNC_ARG;
    }

    if (m4Sz < WC_SHE_M4_SZ || m5Sz < WC_SHE_M5_SZ) {
        return BAD_FUNC_ARG;
    }

    WC_ALLOC_VAR(she, wc_SHE, 1, heap);
    if (!WC_VAR_OK(she)) {
        return MEMORY_E;
    }

    ret = wc_SHE_Init(she, heap, devId);
    if (ret != 0) {
        WC_FREE_VAR(she, heap);
        return ret;
    }

    ret = wc_SHE_LoadKey_Internal(she, m1, m1Sz, m2, m2Sz, m3, m3Sz,
                                  m4, m4Sz, m5, m5Sz);
    WC_FREE_VAR(she, heap);
    return ret;
}

#ifdef WOLF_PRIVATE_KEY_ID
/* -------------------------------------------------------------------------- */
/* wc_SHE_LoadKey_Id                                                           */
/*                                                                            */
/* One-shot with opaque hardware key identifier.                               */
/* Requires a valid devId (not INVALID_DEVID) since the operation dispatches   */
/* to a hardware crypto callback.                                              */
/* -------------------------------------------------------------------------- */
int wc_SHE_LoadKey_Id(
    unsigned char* id, int idLen,
    void* heap, int devId,
    const byte* m1, word32 m1Sz,
    const byte* m2, word32 m2Sz,
    const byte* m3, word32 m3Sz,
    byte* m4, word32 m4Sz,
    byte* m5, word32 m5Sz)
{
    int ret;
    WC_DECLARE_VAR(she, wc_SHE, 1, heap);

    if (id == NULL || m1 == NULL || m2 == NULL || m3 == NULL ||
        m4 == NULL || m5 == NULL) {
        return BAD_FUNC_ARG;
    }

    if (devId == INVALID_DEVID) {
        return BAD_FUNC_ARG;
    }

    if (idLen < 0 || idLen > WC_SHE_MAX_ID_LEN) {
        return BAD_FUNC_ARG;
    }

    if (m1Sz != WC_SHE_M1_SZ || m2Sz != WC_SHE_M2_SZ ||
        m3Sz != WC_SHE_M3_SZ) {
        return BAD_FUNC_ARG;
    }

    if (m4Sz < WC_SHE_M4_SZ || m5Sz < WC_SHE_M5_SZ) {
        return BAD_FUNC_ARG;
    }

    WC_ALLOC_VAR(she, wc_SHE, 1, heap);
    if (!WC_VAR_OK(she)) {
        return MEMORY_E;
    }

    ret = wc_SHE_Init_Id(she, id, idLen, heap, devId);
    if (ret != 0) {
        WC_FREE_VAR(she, heap);
        return ret;
    }

    ret = wc_SHE_LoadKey_Internal(she, m1, m1Sz, m2, m2Sz, m3, m3Sz,
                                  m4, m4Sz, m5, m5Sz);
    WC_FREE_VAR(she, heap);
    return ret;
}

/* -------------------------------------------------------------------------- */
/* wc_SHE_LoadKey_Label                                                        */
/*                                                                            */
/* One-shot with human-readable key label.                                     */
/* Requires a valid devId (not INVALID_DEVID) since the operation dispatches   */
/* to a hardware crypto callback.                                              */
/* -------------------------------------------------------------------------- */
int wc_SHE_LoadKey_Label(
    const char* label,
    void* heap, int devId,
    const byte* m1, word32 m1Sz,
    const byte* m2, word32 m2Sz,
    const byte* m3, word32 m3Sz,
    byte* m4, word32 m4Sz,
    byte* m5, word32 m5Sz)
{
    int ret;
    WC_DECLARE_VAR(she, wc_SHE, 1, heap);

    if (label == NULL || m1 == NULL || m2 == NULL || m3 == NULL ||
        m4 == NULL || m5 == NULL) {
        return BAD_FUNC_ARG;
    }

    if (devId == INVALID_DEVID) {
        return BAD_FUNC_ARG;
    }

    if (XSTRLEN(label) == 0 || XSTRLEN(label) > WC_SHE_MAX_LABEL_LEN) {
        return BAD_FUNC_ARG;
    }

    if (m1Sz != WC_SHE_M1_SZ || m2Sz != WC_SHE_M2_SZ ||
        m3Sz != WC_SHE_M3_SZ) {
        return BAD_FUNC_ARG;
    }

    if (m4Sz < WC_SHE_M4_SZ || m5Sz < WC_SHE_M5_SZ) {
        return BAD_FUNC_ARG;
    }

    WC_ALLOC_VAR(she, wc_SHE, 1, heap);
    if (!WC_VAR_OK(she)) {
        return MEMORY_E;
    }

    ret = wc_SHE_Init_Label(she, label, heap, devId);
    if (ret != 0) {
        WC_FREE_VAR(she, heap);
        return ret;
    }

    ret = wc_SHE_LoadKey_Internal(she, m1, m1Sz, m2, m2Sz, m3, m3Sz,
                                  m4, m4Sz, m5, m5Sz);
    WC_FREE_VAR(she, heap);
    return ret;
}
#endif /* WOLF_PRIVATE_KEY_ID */

/* -------------------------------------------------------------------------- */
/* One-shot Load Key with Verification                                         */
/*                                                                            */
/* Same as the LoadKey variants but also compares the M4/M5 returned by the   */
/* HSM against caller-provided expected values. Returns SIG_VERIFY_E on       */
/* mismatch. The actual M4/M5 from the HSM are still written to the output    */
/* buffers so the caller can inspect them on failure.                          */
/* -------------------------------------------------------------------------- */
static int wc_SHE_VerifyM4M5(
    const byte* m4, word32 m4Sz,
    const byte* m5, word32 m5Sz,
    const byte* m4Expected, word32 m4ExpectedSz,
    const byte* m5Expected, word32 m5ExpectedSz)
{
    if (m4Expected == NULL || m5Expected == NULL) {
        return BAD_FUNC_ARG;
    }

    if (m4ExpectedSz != WC_SHE_M4_SZ || m5ExpectedSz != WC_SHE_M5_SZ ||
        m4Sz < WC_SHE_M4_SZ || m5Sz < WC_SHE_M5_SZ) {
        return BAD_FUNC_ARG;
    }

    if (ConstantCompare(m4, m4Expected, WC_SHE_M4_SZ) != 0 ||
        ConstantCompare(m5, m5Expected, WC_SHE_M5_SZ) != 0) {
        return SIG_VERIFY_E;
    }

    return 0;
}

int wc_SHE_LoadKey_Verify(
    void* heap, int devId,
    const byte* m1, word32 m1Sz,
    const byte* m2, word32 m2Sz,
    const byte* m3, word32 m3Sz,
    byte* m4, word32 m4Sz,
    byte* m5, word32 m5Sz,
    const byte* m4Expected, word32 m4ExpectedSz,
    const byte* m5Expected, word32 m5ExpectedSz)
{
    int ret;

    ret = wc_SHE_LoadKey(heap, devId, m1, m1Sz, m2, m2Sz, m3, m3Sz,
                         m4, m4Sz, m5, m5Sz);
    if (ret != 0) {
        return ret;
    }

    return wc_SHE_VerifyM4M5(m4, m4Sz, m5, m5Sz,
                              m4Expected, m4ExpectedSz,
                              m5Expected, m5ExpectedSz);
}

#ifdef WOLF_PRIVATE_KEY_ID
int wc_SHE_LoadKey_Verify_Id(
    unsigned char* id, int idLen,
    void* heap, int devId,
    const byte* m1, word32 m1Sz,
    const byte* m2, word32 m2Sz,
    const byte* m3, word32 m3Sz,
    byte* m4, word32 m4Sz,
    byte* m5, word32 m5Sz,
    const byte* m4Expected, word32 m4ExpectedSz,
    const byte* m5Expected, word32 m5ExpectedSz)
{
    int ret;

    ret = wc_SHE_LoadKey_Id(id, idLen, heap, devId,
                            m1, m1Sz, m2, m2Sz, m3, m3Sz,
                            m4, m4Sz, m5, m5Sz);
    if (ret != 0) {
        return ret;
    }

    return wc_SHE_VerifyM4M5(m4, m4Sz, m5, m5Sz,
                              m4Expected, m4ExpectedSz,
                              m5Expected, m5ExpectedSz);
}

int wc_SHE_LoadKey_Verify_Label(
    const char* label,
    void* heap, int devId,
    const byte* m1, word32 m1Sz,
    const byte* m2, word32 m2Sz,
    const byte* m3, word32 m3Sz,
    byte* m4, word32 m4Sz,
    byte* m5, word32 m5Sz,
    const byte* m4Expected, word32 m4ExpectedSz,
    const byte* m5Expected, word32 m5ExpectedSz)
{
    int ret;

    ret = wc_SHE_LoadKey_Label(label, heap, devId,
                               m1, m1Sz, m2, m2Sz, m3, m3Sz,
                               m4, m4Sz, m5, m5Sz);
    if (ret != 0) {
        return ret;
    }

    return wc_SHE_VerifyM4M5(m4, m4Sz, m5, m5Sz,
                              m4Expected, m4ExpectedSz,
                              m5Expected, m5ExpectedSz);
}
#endif /* WOLF_PRIVATE_KEY_ID */

#endif /* WOLF_CRYPTO_CB || !NO_WC_SHE_IMPORT_M123 */
#endif /* !NO_WC_SHE_LOADKEY */

/* -------------------------------------------------------------------------- */
/* Export Key                                                                  */
/*                                                                            */
/* When a crypto callback is registered, it can be used to export M1-M5     */
/* from a key slot on an HSM, allowing the key to be re-loaded later via    */
/* the SHE key update protocol.                                              */
/* Any pointer may be NULL to skip that message.                             */
/* -------------------------------------------------------------------------- */
#if defined(WOLF_CRYPTO_CB) && !defined(NO_WC_SHE_EXPORTKEY)
int wc_SHE_ExportKey(wc_SHE* she,
                      byte* m1, word32 m1Sz,
                      byte* m2, word32 m2Sz,
                      byte* m3, word32 m3Sz,
                      byte* m4, word32 m4Sz,
                      byte* m5, word32 m5Sz,
                      const void* ctx)
{
    if (she == NULL) {
        return BAD_FUNC_ARG;
    }

    return wc_CryptoCb_SheExportKey(she,
               m1, m1Sz, m2, m2Sz, m3, m3Sz,
               m4, m4Sz, m5, m5Sz, ctx);
}
#endif /* WOLF_CRYPTO_CB && !NO_WC_SHE_EXPORTKEY */

#endif /* WOLFSSL_SHE */
