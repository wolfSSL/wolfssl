/* wc_she.h
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

#define WC_SHE_KEY_SZ   16  /* AES-128 key size (128 bits) */
#define WC_SHE_UID_SZ   15  /* SHE UID size (120 bits) */

#define WC_SHE_M1_SZ    16  /* UID(15B) | KeyID(4b) | AuthID(4b) */
#define WC_SHE_M2_SZ    32  /* AES-CBC(K1, counter|flags|pad|newkey) */
#define WC_SHE_M3_SZ    16  /* AES-CMAC(K2, M1|M2) */
#define WC_SHE_M4_SZ    32  /* UID|IDs + AES-ECB(K3, counter|pad) */
#define WC_SHE_M5_SZ    16  /* AES-CMAC(K4, M4) */

/* crypto callback sub-types for WC_ALGO_TYPE_SHE */
enum wc_SheType {
    WC_SHE_GET_UID              = 1,
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


/* Initialize SHE context, store heap hint and device ID.
 *   she   - pointer to wc_SHE structure to initialize
 *   heap  - heap hint for internal allocations, or NULL
 *   devId - crypto callback device ID, or INVALID_DEVID for software */
WOLFSSL_API int wc_SHE_Init(wc_SHE* she, void* heap, int devId);

#ifdef WOLF_PRIVATE_KEY_ID
/* Initialize with opaque hardware key identifier.
 * Useful when using callbacks and additional info needs to be attached
 * to the SHE context to determine slot or key group information.
 *   she   - pointer to wc_SHE structure to initialize
 *   id    - opaque key identifier bytes
 *   len   - length of id in bytes (0 to WC_SHE_MAX_ID_LEN)
 *   heap  - heap hint for internal allocations, or NULL
 *   devId - crypto callback device ID */
WOLFSSL_API int wc_SHE_Init_Id(wc_SHE* she, unsigned char* id, int len,
                    void* heap, int devId);

/* Initialize with human-readable key label.
 * Useful when using callbacks and additional info needs to be attached
 * to the SHE context to determine slot or key group information.
 *   she   - pointer to wc_SHE structure to initialize
 *   label - NUL-terminated key label string
 *   heap  - heap hint for internal allocations, or NULL
 *   devId - crypto callback device ID */
WOLFSSL_API int wc_SHE_Init_Label(wc_SHE* she, const char* label,
                       void* heap, int devId);
#endif

/* Scrub all data and zero the context. Safe to call on NULL. */
WOLFSSL_API void wc_SHE_Free(wc_SHE* she);

/* Get UID from hardware.
 *   she   - initialized SHE context
 *   uid   - buffer to receive the 120-bit (15-byte) SHE UID
 *   uidSz - size of uid buffer in bytes
 *   ctx   - read-only caller context (e.g. challenge buffer, HSM handle) */
#if defined(WOLF_CRYPTO_CB) && !defined(NO_WC_SHE_GETUID)
WOLFSSL_API int wc_SHE_GetUID(wc_SHE* she, byte* uid, word32 uidSz,
                   const void* ctx);
#endif

/* Get monotonic counter from hardware.
 *   she     - initialized SHE context
 *   counter - pointer to receive the current counter value.
 *             The SHE spec uses a 28-bit counter. The caller should
 *             increment this value before passing to GenerateM1M2M3/M4M5.
 *   ctx     - read-only caller context */
#if defined(WOLF_CRYPTO_CB) && !defined(NO_WC_SHE_GETCOUNTER)
WOLFSSL_API int wc_SHE_GetCounter(wc_SHE* she, word32* counter,
                   const void* ctx);
#endif

/* Custom KDF constants and header overrides.
 * Useful for some HSMs that support multiple key groups with
 * different derivation constants. */
#ifdef WOLFSSL_SHE_EXTENDED
/* Set KDF constants used in Miyaguchi-Preneel key derivation.
 * Defaults are KEY_UPDATE_ENC_C and KEY_UPDATE_MAC_C from the SHE spec.
 * Either pointer may be NULL to leave that constant unchanged.
 *   she    - initialized SHE context
 *   encC   - 16-byte encryption derivation constant (CENC), or NULL
 *   encCSz - must be WC_SHE_KEY_SZ (16) when encC is non-NULL
 *   macC   - 16-byte MAC derivation constant (CMAC), or NULL
 *   macCSz - must be WC_SHE_KEY_SZ (16) when macC is non-NULL */
WOLFSSL_API int wc_SHE_SetKdfConstants(wc_SHE* she,
                            const byte* encC, word32 encCSz,
                            const byte* macC, word32 macCSz);

/* Override M2 cleartext header (first 16 bytes of M2 before encryption).
 * When set, GenerateM1M2M3 uses this instead of auto-building from
 * counter and flags. The header is: counter(28b)|flags(4b)|zeros(96b).
 *   she      - initialized SHE context
 *   header   - 16-byte cleartext header block
 *   headerSz - must be WC_SHE_KEY_SZ (16) */
WOLFSSL_API int wc_SHE_SetM2Header(wc_SHE* she,
                            const byte* header, word32 headerSz);

/* Override M4 cleartext counter block (16-byte block encrypted with K3).
 * When set, GenerateM4M5 uses this instead of auto-building from counter.
 * The block is: counter(28b)|1(1b)|zeros(99b).
 *   she      - initialized SHE context
 *   header   - 16-byte cleartext counter block
 *   headerSz - must be WC_SHE_KEY_SZ (16) */
WOLFSSL_API int wc_SHE_SetM4Header(wc_SHE* she,
                            const byte* header, word32 headerSz);
#endif /* WOLFSSL_SHE_EXTENDED */

/* Import externally-provided M1/M2/M3 into context.
 * Sets the generated flag so the callback for GenerateM4M5 can
 * read M1/M2/M3 from the context to send to hardware.
 *   she  - initialized SHE context
 *   m1   - 16-byte M1 message (UID | KeyID | AuthID)
 *   m1Sz - must be WC_SHE_M1_SZ (16)
 *   m2   - 32-byte M2 message (encrypted counter|flags|pad|newkey)
 *   m2Sz - must be WC_SHE_M2_SZ (32)
 *   m3   - 16-byte M3 message (CMAC over M1|M2)
 *   m3Sz - must be WC_SHE_M3_SZ (16) */
#if defined(WOLF_CRYPTO_CB) || !defined(NO_WC_SHE_IMPORT_M123)
WOLFSSL_API int wc_SHE_ImportM1M2M3(wc_SHE* she,
                          const byte* m1, word32 m1Sz,
                          const byte* m2, word32 m2Sz,
                          const byte* m3, word32 m3Sz);
#endif

/* Generate M1/M2/M3 for the SHE key update protocol and write to
 * caller-provided buffers.
 *
 *   she        - initialized SHE context
 *   uid        - 15-byte SHE UID (120-bit ECU/module identifier)
 *   uidSz      - must be WC_SHE_UID_SZ (15)
 *   authKeyId  - slot ID of the authorizing key (0-14, e.g.
 *                MASTER_ECU_KEY=1, KEY_1..KEY_10=4..13)
 *   authKey    - 16-byte value of the authorizing key. Used to derive
 *                K1 (encryption) and K2 (MAC).
 *   authKeySz  - must be WC_SHE_KEY_SZ (16)
 *   targetKeyId - slot ID of the key being loaded (1-14)
 *   newKey     - 16-byte value of the new key to load. Placed in M2
 *                cleartext and used to derive K3/K4 for M4/M5.
 *   newKeySz   - must be WC_SHE_KEY_SZ (16)
 *   counter    - 28-bit monotonic counter value. Must be strictly greater
 *                than the counter stored in the target slot on the SHE.
 *   flags      - key protection flags (lower 4 bits of the counter|flags
 *                word in M2).
 *   m1         - output buffer for M1 (16 bytes)
 *   m1Sz       - size of m1 buffer, must be >= WC_SHE_M1_SZ
 *   m2         - output buffer for M2 (32 bytes)
 *   m2Sz       - size of m2 buffer, must be >= WC_SHE_M2_SZ
 *   m3         - output buffer for M3 (16 bytes)
 *   m3Sz       - size of m3 buffer, must be >= WC_SHE_M3_SZ */
WOLFSSL_API int wc_SHE_GenerateM1M2M3(wc_SHE* she,
                      const byte* uid, word32 uidSz,
                      byte authKeyId, const byte* authKey, word32 authKeySz,
                      byte targetKeyId, const byte* newKey, word32 newKeySz,
                      word32 counter, byte flags,
                      byte* m1, word32 m1Sz,
                      byte* m2, word32 m2Sz,
                      byte* m3, word32 m3Sz);

/* Generate M4/M5 verification messages and write to caller-provided
 * buffers. Independent of M1/M2/M3, can be called on a separate context.
 *
 *   she         - initialized SHE context
 *   uid         - 15-byte SHE UID (same UID used for M1)
 *   uidSz       - must be WC_SHE_UID_SZ (15)
 *   authKeyId   - slot ID of the authorizing key (same as in M1)
 *   targetKeyId - slot ID of the key being loaded (same as in M1)
 *   newKey      - 16-byte value of the new key. Used to derive K3
 *                 (encryption for M4 counter block) and K4 (MAC for M5).
 *   newKeySz    - must be WC_SHE_KEY_SZ (16)
 *   counter     - 28-bit monotonic counter (same value as in M2)
 *   m4          - output buffer for M4 (32 bytes)
 *   m4Sz        - size of m4 buffer, must be >= WC_SHE_M4_SZ
 *   m5          - output buffer for M5 (16 bytes)
 *   m5Sz        - size of m5 buffer, must be >= WC_SHE_M5_SZ */
WOLFSSL_API int wc_SHE_GenerateM4M5(wc_SHE* she,
                      const byte* uid, word32 uidSz,
                      byte authKeyId, byte targetKeyId,
                      const byte* newKey, word32 newKeySz,
                      word32 counter,
                      byte* m4, word32 m4Sz,
                      byte* m5, word32 m5Sz);

/* Export a key from hardware in SHE loadable format (M1-M5).
 * Some HSMs allow exporting certain key slots (e.g. RAM key) so they
 * can be re-loaded later via the SHE key update protocol.
 *   she   - initialized SHE context
 *   m1    - output buffer for M1 (16 bytes), or NULL to skip
 *   m1Sz  - size of m1 buffer
 *   m2    - output buffer for M2 (32 bytes), or NULL to skip
 *   m2Sz  - size of m2 buffer
 *   m3    - output buffer for M3 (16 bytes), or NULL to skip
 *   m3Sz  - size of m3 buffer
 *   m4    - output buffer for M4 (32 bytes), or NULL to skip
 *   m4Sz  - size of m4 buffer
 *   m5    - output buffer for M5 (16 bytes), or NULL to skip
 *   m5Sz  - size of m5 buffer
 *   ctx   - read-only caller context passed to the callback */
#if defined(WOLF_CRYPTO_CB) && !defined(NO_WC_SHE_EXPORTKEY)
WOLFSSL_API int wc_SHE_ExportKey(wc_SHE* she,
                      byte* m1, word32 m1Sz,
                      byte* m2, word32 m2Sz,
                      byte* m3, word32 m3Sz,
                      byte* m4, word32 m4Sz,
                      byte* m5, word32 m5Sz,
                      const void* ctx);
#endif

/* Internal: Miyaguchi-Preneel AES-128 one-way compression.
 * H_0 = 0, H_i = E_{H_{i-1}}(M_i) XOR M_i XOR H_{i-1}.
 * Only valid for AES-128 where key size equals block size.
 * Exposed via WOLFSSL_TEST_VIS for testing.
 *   aes   - caller-owned, already-initialized Aes structure
 *   in    - input data (e.g. BaseKey || KDF_Constant, 32 bytes)
 *   inSz  - length of input in bytes (zero-padded to block boundary)
 *   out   - output buffer for 16-byte compressed result */
WOLFSSL_TEST_VIS int wc_SHE_AesMp16(Aes* aes, const byte* in, word32 inSz,
                                     byte* out);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFSSL_SHE */
#endif /* WOLF_CRYPT_SHE_H */
