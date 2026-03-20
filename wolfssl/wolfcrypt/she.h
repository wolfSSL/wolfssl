/* she.h
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


#ifndef WOLF_CRYPT_SHE_H
#define WOLF_CRYPT_SHE_H

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_SHE

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/aes.h>

#ifdef __cplusplus
    extern "C" {
#endif

#define WC_SHE_KEY_SZ   16
#define WC_SHE_UID_SZ   15

#define WC_SHE_M1_SZ    16
#define WC_SHE_M2_SZ    32
#define WC_SHE_M3_SZ    16
#define WC_SHE_M4_SZ    32
#define WC_SHE_M5_SZ    16

/* crypto callback sub-types for WC_ALGO_TYPE_SHE */
enum wc_SheType {
    WC_SHE_SET_UID              = 1,
    WC_SHE_GET_COUNTER          = 2,
    WC_SHE_GENERATE_M1M2M3      = 3,
    WC_SHE_GENERATE_M4M5        = 4,
    WC_SHE_EXPORT_KEY           = 5
};

/* test flags (only used for KATs) */
#define WC_SHE_MASTER_ECU_KEY_ID    1
#define WC_SHE_FLAG_WRITE_PROTECT   0x01
#define WC_SHE_FLAG_BOOT_PROTECT    0x02

/* internal field offsets and shifts for message construction */
#define WC_SHE_M1_KID_OFFSET  15
#define WC_SHE_M1_KID_SHIFT   4
#define WC_SHE_M1_AID_SHIFT   0

#define WC_SHE_M2_COUNT_SHIFT  4
#define WC_SHE_M2_FLAGS_SHIFT  0
#define WC_SHE_M2_KEY_OFFSET   16

#define WC_SHE_M4_KID_OFFSET    15
#define WC_SHE_M4_KID_SHIFT     4
#define WC_SHE_M4_AID_SHIFT     0
#define WC_SHE_M4_COUNT_OFFSET  16
#define WC_SHE_M4_COUNT_SHIFT   4
#define WC_SHE_M4_COUNT_PAD     0x8

/* SHE KDF constants (Miyaguchi-Preneel input) */
#define WC_SHE_KEY_UPDATE_ENC_C { \
    0x01, 0x01, 0x53, 0x48, \
    0x45, 0x00, 0x80, 0x00, \
    0x00, 0x00, 0x00, 0x00, \
    0x00, 0x00, 0x00, 0xB0  \
}

#define WC_SHE_KEY_UPDATE_MAC_C { \
    0x01, 0x02, 0x53, 0x48, \
    0x45, 0x00, 0x80, 0x00, \
    0x00, 0x00, 0x00, 0x00, \
    0x00, 0x00, 0x00, 0xB0  \
}

enum {
    WC_SHE_MAX_ID_LEN    = 32,
    WC_SHE_MAX_LABEL_LEN = 32
};

typedef struct wc_SHE {
#ifdef WOLFSSL_SHE_EXTENDED
    /* Custom KDF constants and header overrides.
     * Useful for some HSMs that support multiple key groups with
     * different derivation constants. */
    byte   kdfEncC[WC_SHE_KEY_SZ];
    byte   kdfMacC[WC_SHE_KEY_SZ];
    byte   m2pHeader[WC_SHE_KEY_SZ];
    byte   m4pHeader[WC_SHE_KEY_SZ];
    byte   kdfEncOverride;
    byte   kdfMacOverride;
    byte   m2pOverride;
    byte   m4pOverride;
#endif

#if defined(WOLF_CRYPTO_CB) || !defined(NO_WC_SHE_IMPORT_M123)
    byte   m1[WC_SHE_M1_SZ];
    byte   m2[WC_SHE_M2_SZ];
    byte   m3[WC_SHE_M3_SZ];
    byte   generated;
#endif

    void*  heap;
    int    devId;
#ifdef WOLF_CRYPTO_CB
    void*  devCtx;
#endif
#ifdef WOLF_PRIVATE_KEY_ID
    byte id[WC_SHE_MAX_ID_LEN];
    int  idLen;
    char label[WC_SHE_MAX_LABEL_LEN];
    int  labelLen;
#endif
} wc_SHE;


/* Initialize SHE context, store heap hint and device ID */
WOLFSSL_API int wc_SHE_Init(wc_SHE* she, void* heap, int devId);

#ifdef WOLF_PRIVATE_KEY_ID
/* Initialize with opaque hardware key identifier */
WOLFSSL_API int wc_SHE_Init_Id(wc_SHE* she, unsigned char* id, int len,
                    void* heap, int devId);
/* Initialize with human-readable key label */
WOLFSSL_API int wc_SHE_Init_Label(wc_SHE* she, const char* label,
                       void* heap, int devId);
#endif

/* Scrub and zero the context */
WOLFSSL_API void wc_SHE_Free(wc_SHE* she);

/* Get UID from hardware; callback required (WC_SHE_SET_UID) */
#if defined(WOLF_CRYPTO_CB) && !defined(NO_WC_SHE_GETUID)
WOLFSSL_API int wc_SHE_GetUID(wc_SHE* she, byte* uid, word32 uidSz,
                   const void* ctx);
#endif

/* Get counter from hardware; callback required */
#if defined(WOLF_CRYPTO_CB) && !defined(NO_WC_SHE_GETCOUNTER)
WOLFSSL_API int wc_SHE_GetCounter(wc_SHE* she, word32* counter,
                   const void* ctx);
#endif

/* Custom KDF constants and header overrides.
 * Useful for some HSMs that support multiple key groups with
 * different derivation constants. */
#ifdef WOLFSSL_SHE_EXTENDED
/* Set KDF constants (CENC/CMAC). Defaults set by Init. NULL to skip. */
WOLFSSL_API int wc_SHE_SetKdfConstants(wc_SHE* she,
                            const byte* encC, word32 encCSz,
                            const byte* macC, word32 macCSz);

/* Override M2P cleartext header. Skips auto-build from counter/flags. */
WOLFSSL_API int wc_SHE_SetM2Header(wc_SHE* she,
                            const byte* header, word32 headerSz);

/* Override M4P cleartext header. Skips auto-build from counter. */
WOLFSSL_API int wc_SHE_SetM4Header(wc_SHE* she,
                            const byte* header, word32 headerSz);
#endif /* WOLFSSL_SHE_EXTENDED */

/* Import externally-provided M1/M2/M3 into context; sets generated flag */
#if defined(WOLF_CRYPTO_CB) || !defined(NO_WC_SHE_IMPORT_M123)
WOLFSSL_API int wc_SHE_ImportM1M2M3(wc_SHE* she,
                          const byte* m1, word32 m1Sz,
                          const byte* m2, word32 m2Sz,
                          const byte* m3, word32 m3Sz);
#endif

/* Generate M1/M2/M3 and write to caller buffers */
WOLFSSL_API int wc_SHE_GenerateM1M2M3(wc_SHE* she,
                      const byte* uid, word32 uidSz,
                      byte authKeyId, const byte* authKey, word32 authKeySz,
                      byte targetKeyId, const byte* newKey, word32 newKeySz,
                      word32 counter, byte flags,
                      byte* m1, word32 m1Sz,
                      byte* m2, word32 m2Sz,
                      byte* m3, word32 m3Sz);

/* Generate M4/M5 and write to caller buffers */
WOLFSSL_API int wc_SHE_GenerateM4M5(wc_SHE* she,
                      const byte* uid, word32 uidSz,
                      byte authKeyId, byte targetKeyId,
                      const byte* newKey, word32 newKeySz,
                      word32 counter,
                      byte* m4, word32 m4Sz,
                      byte* m5, word32 m5Sz);

/* Export key from hardware as M1-M5; callback required.
 * Some HSMs allow exporting certain key slots (e.g. RAM key) in SHE format. */
#if defined(WOLF_CRYPTO_CB) && !defined(NO_WC_SHE_EXPORTKEY)
WOLFSSL_API int wc_SHE_ExportKey(wc_SHE* she,
                      byte* m1, word32 m1Sz,
                      byte* m2, word32 m2Sz,
                      byte* m3, word32 m3Sz,
                      byte* m4, word32 m4Sz,
                      byte* m5, word32 m5Sz,
                      const void* ctx);
#endif

/* Internal: Miyaguchi-Preneel AES-128 compression, exposed for testing */
WOLFSSL_TEST_VIS int wc_She_AesMp16(Aes* aes, const byte* in, word32 inSz,
                                     byte* out);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFSSL_SHE */
#endif /* WOLF_CRYPT_SHE_H */
