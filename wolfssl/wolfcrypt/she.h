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
    WC_SHE_GENERATE_M1M2M3      = 2,
    WC_SHE_GENERATE_M4M5        = 3,
    WC_SHE_EXPORT_KEY           = 4
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
    byte   uid[WC_SHE_UID_SZ];
    byte   authKeyId;
    byte   targetKeyId;
    byte   authKey[WC_SHE_KEY_SZ];
    byte   newKey[WC_SHE_KEY_SZ];
    word32 counter;
    byte   flags;

    byte   kdfEncC[WC_SHE_KEY_SZ];  /* KDF encryption constant (CENC) */
    byte   kdfMacC[WC_SHE_KEY_SZ];  /* KDF authentication constant (CMAC) */
    byte   m2pHeader[WC_SHE_KEY_SZ]; /* M2P cleartext header (counter|flags|pad) */
    byte   m4pHeader[WC_SHE_KEY_SZ]; /* M4P cleartext header (counter|pad) */
    byte   m2pOverride;  /* set by SetM2Header to skip auto-build */
    byte   m4pOverride;  /* set by SetM4Header to skip auto-build */

    byte   m1[WC_SHE_M1_SZ];
    byte   m2[WC_SHE_M2_SZ];
    byte   m3[WC_SHE_M3_SZ];
    byte   m4[WC_SHE_M4_SZ];
    byte   m5[WC_SHE_M5_SZ];

    byte   generated;
    byte   verified;

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

/* Scrub key material and zero the context */
WOLFSSL_API void wc_SHE_Free(wc_SHE* she);

/* Set UID; callback optional (WC_SHE_SET_UID) */
WOLFSSL_API int wc_SHE_SetUID(wc_SHE* she, const byte* uid, word32 uidSz,
                   const void* ctx);

/* Set authorizing key slot ID and value */
WOLFSSL_API int wc_SHE_SetAuthKey(wc_SHE* she, byte authKeyId,
                       const byte* authKey, word32 keySz);

/* Set target key slot ID and new key value */
WOLFSSL_API int wc_SHE_SetNewKey(wc_SHE* she, byte targetKeyId,
                      const byte* newKey, word32 keySz);

/* Set monotonic counter value for M2 */
WOLFSSL_API int wc_SHE_SetCounter(wc_SHE* she, word32 counter);

/* Set flag byte for M2 */
WOLFSSL_API int wc_SHE_SetFlags(wc_SHE* she, byte flags);

/* Set KDF constants (CENC/CMAC) used for key derivation.
 * Defaults are set by Init. Either pointer may be NULL to skip. */
WOLFSSL_API int wc_SHE_SetKdfConstants(wc_SHE* she,
                            const byte* encC, word32 encCSz,
                            const byte* macC, word32 macCSz);

/* Override M2P cleartext header (first 16 bytes before KID').
 * Skips auto-build from counter/flags in GenerateM1M2M3. */
WOLFSSL_API int wc_SHE_SetM2Header(wc_SHE* she,
                            const byte* header, word32 headerSz);

/* Override M4P cleartext header (16-byte counter block).
 * Skips auto-build from counter in GenerateM4M5. */
WOLFSSL_API int wc_SHE_SetM4Header(wc_SHE* she,
                            const byte* header, word32 headerSz);

/* Generate M1/M2/M3 from the current context */
WOLFSSL_API int wc_SHE_GenerateM1M2M3(wc_SHE* she);

/* Miyaguchi-Preneel AES-128 compression (internal, exposed for testing) */
WOLFSSL_TEST_VIS int wc_She_AesMp16(Aes* aes, const byte* in, word32 inSz,
                                     byte* out);

/* Generate M4/M5 verification messages; callback optional (WC_SHE_GENERATE_M4M5) */
WOLFSSL_API int wc_SHE_GenerateM4M5(wc_SHE* she);

/* Export M1-M5 into caller buffers; NULL to skip; callback optional (WC_SHE_EXPORT_KEY) */
WOLFSSL_API int wc_SHE_ExportKey(wc_SHE* she,
                      byte* m1, word32 m1Sz,
                      byte* m2, word32 m2Sz,
                      byte* m3, word32 m3Sz,
                      byte* m4, word32 m4Sz,
                      byte* m5, word32 m5Sz,
                      const void* ctx);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFSSL_SHE */
#endif /* WOLF_CRYPT_SHE_H */
