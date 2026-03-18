/* she.c
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

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/cmac.h>
#include <wolfssl/wolfcrypt/she.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#ifdef WOLF_CRYPTO_CB
    #include <wolfssl/wolfcrypt/cryptocb.h>
#endif

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
int wc_She_AesMp16(Aes* aes, const byte* in, word32 inSz, byte* out)
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
    const byte encC[] = WC_SHE_KEY_UPDATE_ENC_C;
    const byte macC[] = WC_SHE_KEY_UPDATE_MAC_C;

    if (she == NULL) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(she, 0, sizeof(wc_SHE));
    she->heap  = heap;
    she->devId = devId;
    XMEMCPY(she->kdfEncC, encC, WC_SHE_KEY_SZ);
    XMEMCPY(she->kdfMacC, macC, WC_SHE_KEY_SZ);
    /* m2pHeader/m4pHeader are zero from XMEMSET ΓÇö correct for counter=0 */

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

    if (she == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = wc_SHE_Init(she, heap, devId);
    if (ret != 0) {
        return ret;
    }

    if (len < 0 || len > WC_SHE_MAX_ID_LEN) {
        return BUFFER_E;
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
/* Setter functions                                                           */
/* -------------------------------------------------------------------------- */

int wc_SHE_SetUID(wc_SHE* she, const byte* uid, word32 uidSz,
                   const void* ctx)
{
#ifdef WOLF_CRYPTO_CB
    int ret;
#endif

    if (she == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLF_CRYPTO_CB
    /* Try callback first if a device is registered */
    if (she->devId != INVALID_DEVID) {
        ret = wc_CryptoCb_SheSetUid(she, uid, uidSz, ctx);
        if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE)) {
            return ret;
        }
        /* fall-through to software path */
    }
#else
    (void)ctx;
#endif

    /* Software path: copy caller-provided UID */
    if (uid == NULL || uidSz != WC_SHE_UID_SZ) {
        return BAD_FUNC_ARG;
    }

    XMEMCPY(she->uid, uid, WC_SHE_UID_SZ);
    return 0;
}

int wc_SHE_SetAuthKey(wc_SHE* she, byte authKeyId,
                       const byte* authKey, word32 keySz)
{
    if (she == NULL || authKey == NULL || keySz != WC_SHE_KEY_SZ) {
        return BAD_FUNC_ARG;
    }

    she->authKeyId = authKeyId;
    XMEMCPY(she->authKey, authKey, WC_SHE_KEY_SZ);
    return 0;
}

int wc_SHE_SetNewKey(wc_SHE* she, byte targetKeyId,
                      const byte* newKey, word32 keySz)
{
    if (she == NULL || newKey == NULL || keySz != WC_SHE_KEY_SZ) {
        return BAD_FUNC_ARG;
    }

    she->targetKeyId = targetKeyId;
    XMEMCPY(she->newKey, newKey, WC_SHE_KEY_SZ);
    return 0;
}

int wc_SHE_SetCounter(wc_SHE* she, word32 counter)
{
    if (she == NULL) {
        return BAD_FUNC_ARG;
    }

    she->counter = counter;
    return 0;
}

int wc_SHE_SetFlags(wc_SHE* she, byte flags)
{
    if (she == NULL) {
        return BAD_FUNC_ARG;
    }

    she->flags = flags;
    return 0;
}

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
    }

    if (macC != NULL) {
        if (macCSz != WC_SHE_KEY_SZ) {
            return BAD_FUNC_ARG;
        }
        XMEMCPY(she->kdfMacC, macC, WC_SHE_KEY_SZ);
    }

    return 0;
}

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

/* Build M2P/M4P headers from counter and flags using standard SHE packing.
 * M2P header: counter(28b) | flags(4b) | zeros(96b) = 16 bytes
 * M4P header: counter(28b) | 1(1b) | zeros(99b) = 16 bytes
 * Called internally by GenerateM1M2M3/GenerateM4M5 unless overridden. */
static void she_build_headers(wc_SHE* she)
{
    word32 field;

    if (!she->m2pOverride) {
        XMEMSET(she->m2pHeader, 0, WC_SHE_KEY_SZ);
        field = (she->counter << WC_SHE_M2_COUNT_SHIFT) |
                (she->flags   << WC_SHE_M2_FLAGS_SHIFT);
        she_store_be32(she->m2pHeader, field);
    }

    if (!she->m4pOverride) {
        XMEMSET(she->m4pHeader, 0, WC_SHE_KEY_SZ);
        field = (she->counter << WC_SHE_M4_COUNT_SHIFT) | WC_SHE_M4_COUNT_PAD;
        she_store_be32(she->m4pHeader, field);
    }
}

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

/* -------------------------------------------------------------------------- */
/* M1/M2/M3 generation                                                       */
/*                                                                            */
/* Derives K1 and K2 from AuthKey via Miyaguchi-Preneel, then builds:        */
/*   M1 = UID | TargetKeyID | AuthKeyID                                      */
/*   M2 = AES-CBC(K1, IV=0, counter|flags|pad|newkey)                        */
/*   M3 = AES-CMAC(K2, M1 | M2)                                             */
/*                                                                            */
/* Ported from wolfHSM wh_She_GenerateLoadableKey() in wh_she_crypto.c.      */
/* -------------------------------------------------------------------------- */
int wc_SHE_GenerateM1M2M3(wc_SHE* she)
{
    int    ret = 0;
    byte   k1[WC_SHE_KEY_SZ];
    byte   k2[WC_SHE_KEY_SZ];
    byte   kdfInput[WC_SHE_KEY_SZ * 2];
    word32 cmacSz = AES_BLOCK_SIZE;
    WC_DECLARE_VAR(aes, Aes, 1, 0);
    WC_DECLARE_VAR(cmac, Cmac, 1, 0);

    if (she == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Build M2P/M4P headers from counter/flags (skipped if overridden) */
    she_build_headers(she);

#ifdef WOLF_CRYPTO_CB
    /* Try callback first ΓÇö hardware may generate M1/M2/M3 directly */
    if (she->devId != INVALID_DEVID) {
        ret = wc_CryptoCb_SheGenerateM1M2M3(she, NULL);
        if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE)) {
            if (ret == 0) {
                she->generated = 1;
            }
            return ret;
        }
        /* fall-through to software path */
        ret = 0;
    }
#endif

    WC_ALLOC_VAR(aes, Aes, 1, she->heap);
    if (!WC_VAR_OK(aes)) {
        return MEMORY_E;
    }

    WC_ALLOC_VAR(cmac, Cmac, 1, she->heap);
    if (!WC_VAR_OK(cmac)) {
        WC_FREE_VAR(aes, she->heap);
        return MEMORY_E;
    }

    /* Init AES once — used by both MP16 and CBC */
    ret = wc_AesInit(aes, she->heap, she->devId);
    if (ret != 0) {
        WC_FREE_VAR(aes, she->heap);
        WC_FREE_VAR(cmac, she->heap);
        return ret;
    }

    /* ---- Derive K1 = AES-MP(AuthKey || CENC) ---- */
    XMEMCPY(kdfInput, she->authKey, WC_SHE_KEY_SZ);
    XMEMCPY(kdfInput + WC_SHE_KEY_SZ, she->kdfEncC, WC_SHE_KEY_SZ);
    ret = wc_She_AesMp16(aes, kdfInput, WC_SHE_KEY_SZ * 2, k1);

    /* ---- Build M1: UID(15B) | TargetKeyID(4b) | AuthKeyID(4b) ---- */
    if (ret == 0) {
        XMEMCPY(she->m1, she->uid, WC_SHE_UID_SZ);
        she->m1[WC_SHE_M1_KID_OFFSET] =
            (byte)((she->targetKeyId << WC_SHE_M1_KID_SHIFT) |
                   (she->authKeyId   << WC_SHE_M1_AID_SHIFT));
    }

    /* ---- Build cleartext M2 and encrypt with K1 ---- */
    if (ret == 0) {
        /* M2P = m2pHeader(16B) | newKey(16B) */
        XMEMCPY(she->m2, she->m2pHeader, WC_SHE_KEY_SZ);
        XMEMCPY(she->m2 + WC_SHE_M2_KEY_OFFSET, she->newKey, WC_SHE_KEY_SZ);

        /* Encrypt M2 in-place with AES-128-CBC, IV = 0 */
        ret = wc_AesSetKey(aes, k1, WC_SHE_KEY_SZ, NULL, AES_ENCRYPTION);
        if (ret == 0) {
            ret = wc_AesCbcEncrypt(aes, she->m2, she->m2, WC_SHE_M2_SZ);
        }
    }

    /* ---- Derive K2 = AES-MP(AuthKey || CMAC) ---- */
    if (ret == 0) {
        XMEMCPY(kdfInput + WC_SHE_KEY_SZ, she->kdfMacC, WC_SHE_KEY_SZ);
        ret = wc_She_AesMp16(aes, kdfInput, WC_SHE_KEY_SZ * 2, k2);
    }

    /* ---- Build M3 = AES-CMAC(K2, M1 || M2) ---- */
    if (ret == 0) {
        ret = wc_InitCmac_ex(cmac, k2, WC_SHE_KEY_SZ, WC_CMAC_AES,
                              NULL, she->heap, she->devId);
    }
    if (ret == 0) {
        ret = wc_CmacUpdate(cmac, she->m1, WC_SHE_M1_SZ);
    }
    if (ret == 0) {
        ret = wc_CmacUpdate(cmac, she->m2, WC_SHE_M2_SZ);
    }
    if (ret == 0) {
        cmacSz = AES_BLOCK_SIZE;
        ret = wc_CmacFinal(cmac, she->m3, &cmacSz);
    }

    if (ret == 0) {
        she->generated = 1;
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
/* -------------------------------------------------------------------------- */
int wc_SHE_GenerateM4M5(wc_SHE* she)
{
    int    ret = 0;
    byte   k3[WC_SHE_KEY_SZ];
    byte   k4[WC_SHE_KEY_SZ];
    byte   kdfInput[WC_SHE_KEY_SZ * 2];
    word32 cmacSz;
    WC_DECLARE_VAR(aes, Aes, 1, 0);
    WC_DECLARE_VAR(cmac, Cmac, 1, 0);

    if (she == NULL) {
        return BAD_FUNC_ARG;
    }
    if (!she->generated) {
        return BAD_STATE_E;
    }

#ifdef WOLF_CRYPTO_CB
    /* Try callback first — sends M1/M2/M3 to HW, receives M4/M5 */
    if (she->devId != INVALID_DEVID) {
        ret = wc_CryptoCb_SheGenerateM4M5(she, NULL);
        if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE)) {
            if (ret == 0) {
                she->verified = 1;
            }
            return ret;
        }
        /* fall-through to software path */
    }
#endif

    WC_ALLOC_VAR(aes, Aes, 1, she->heap);
    if (!WC_VAR_OK(aes)) {
        return MEMORY_E;
    }

    WC_ALLOC_VAR(cmac, Cmac, 1, she->heap);
    if (!WC_VAR_OK(cmac)) {
        WC_FREE_VAR(aes, she->heap);
        return MEMORY_E;
    }

    /* Init AES once — used by both MP16 and ECB */
    ret = wc_AesInit(aes, she->heap, she->devId);
    if (ret != 0) {
        WC_FREE_VAR(aes, she->heap);
        WC_FREE_VAR(cmac, she->heap);
        return ret;
    }

    /* ---- Derive K3 = AES-MP(NewKey || CENC) ---- */
    XMEMCPY(kdfInput, she->newKey, WC_SHE_KEY_SZ);
    XMEMCPY(kdfInput + WC_SHE_KEY_SZ, she->kdfEncC, WC_SHE_KEY_SZ);
    ret = wc_She_AesMp16(aes, kdfInput, WC_SHE_KEY_SZ * 2, k3);

    /* ---- Build M4: UID|IDs header + AES-ECB(K3, m4pHeader) ---- */
    if (ret == 0) {
        XMEMSET(she->m4, 0, WC_SHE_M4_SZ);

        XMEMCPY(she->m4, she->uid, WC_SHE_UID_SZ);
        she->m4[WC_SHE_M4_KID_OFFSET] =
            (byte)((she->targetKeyId << WC_SHE_M4_KID_SHIFT) |
                   (she->authKeyId   << WC_SHE_M4_AID_SHIFT));

        /* Copy pre-built M4P header (counter|pad) into M4 counter block */
        XMEMCPY(she->m4 + WC_SHE_M4_COUNT_OFFSET, she->m4pHeader,
                 WC_SHE_KEY_SZ);

        /* Encrypt the 16-byte counter block in-place with AES-ECB */
        ret = wc_AesSetKey(aes, k3, WC_SHE_KEY_SZ, NULL, AES_ENCRYPTION);
        if (ret == 0) {
            ret = wc_AesEncryptDirect(aes,
                    she->m4 + WC_SHE_M4_COUNT_OFFSET,
                    she->m4 + WC_SHE_M4_COUNT_OFFSET);
        }
    }

    /* ---- Derive K4 = AES-MP(NewKey || CMAC) ---- */
    if (ret == 0) {
        XMEMCPY(kdfInput + WC_SHE_KEY_SZ, she->kdfMacC, WC_SHE_KEY_SZ);
        ret = wc_She_AesMp16(aes, kdfInput, WC_SHE_KEY_SZ * 2, k4);
    }

    /* ---- Build M5 = AES-CMAC(K4, M4) ---- */
    if (ret == 0) {
        cmacSz = AES_BLOCK_SIZE;
        ret = wc_AesCmacGenerate_ex(cmac, she->m5, &cmacSz,
                she->m4, WC_SHE_M4_SZ, k4, WC_SHE_KEY_SZ,
                she->heap, she->devId);
    }

    if (ret == 0) {
        she->verified = 1;
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
/* Export Key (callback optional)                                             */
/*                                                                            */
/* Software: copies computed messages from context into caller buffers.       */
/* Any pointer may be NULL to skip that message.                             */
/* M1/M2/M3 require generated state, M4/M5 require verified state.          */
/* Callback: asks hardware to export the key as M1-M5.                       */
/* -------------------------------------------------------------------------- */
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

    /* Verify buffer sizes for any non-NULL pointers */
    if ((m1 != NULL && m1Sz < WC_SHE_M1_SZ) ||
        (m2 != NULL && m2Sz < WC_SHE_M2_SZ) ||
        (m3 != NULL && m3Sz < WC_SHE_M3_SZ) ||
        (m4 != NULL && m4Sz < WC_SHE_M4_SZ) ||
        (m5 != NULL && m5Sz < WC_SHE_M5_SZ)) {
        return BUFFER_E;
    }

#ifdef WOLF_CRYPTO_CB
    if (she->devId != INVALID_DEVID) {
        int ret = wc_CryptoCb_SheExportKey(she,
                      m1, m1Sz, m2, m2Sz, m3, m3Sz,
                      m4, m4Sz, m5, m5Sz, ctx);
        if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE)) {
            return ret;
        }
        /* fall-through to software path */
    }
#endif
    (void)ctx;

    /* Export M1/M2/M3 if requested */
    if (m1 != NULL || m2 != NULL || m3 != NULL) {
        if (!she->generated) {
            return BAD_STATE_E;
        }
        if (m1 != NULL) {
            XMEMCPY(m1, she->m1, WC_SHE_M1_SZ);
        }
        if (m2 != NULL) {
            XMEMCPY(m2, she->m2, WC_SHE_M2_SZ);
        }
        if (m3 != NULL) {
            XMEMCPY(m3, she->m3, WC_SHE_M3_SZ);
        }
    }

    /* Export M4/M5 if requested */
    if (m4 != NULL || m5 != NULL) {
        if (!she->verified) {
            return BAD_STATE_E;
        }
        if (m4 != NULL) {
            XMEMCPY(m4, she->m4, WC_SHE_M4_SZ);
        }
        if (m5 != NULL) {
            XMEMCPY(m5, she->m5, WC_SHE_M5_SZ);
        }
    }

    return 0;
}

#endif /* WOLFSSL_SHE */
