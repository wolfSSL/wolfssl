/* cracen_hw.h
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

/* Seam between the crypto callback handlers and the CRACEN hardware. The only
 * file that touches registers is cracen_hw_bare.c; cracen_hw_shim.c implements
 * the same functions for a host compile (WOLFSSL_CRACEN_HOST_TEST) and
 * declines everything.
 *
 * Every function returns 0 on success, CRYPTOCB_UNAVAILABLE when the request
 * must go to software, or a negative wolfCrypt error.
 */

#ifndef WOLFSSL_CRACEN_HW_H
#define WOLFSSL_CRACEN_HW_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef __cplusplus
    extern "C" {
#endif

/* Cryptomaster DMA descriptor, as the hardware reads it. */
typedef struct wc_CracenDesc {
    word32 addr;
    word32 next;
    word32 len;
    word32 tag;
} wc_CracenDesc;

/* One contiguous in/out span for a block cipher run. */
typedef struct wc_CracenSeg {
    const byte* in;
    byte*       out;
    word32      sz;
} wc_CracenSeg;

#define WC_CRACEN_MAX_SEGS 2

typedef struct wc_CracenHwInfo {
    word32 engines;    /* CRYPTMSTRHW.INCLIPSHWCFG                       */
    word32 aesModes;   /* CRYPTMSTRHW.BA411EAESHWCFG1                     */
    word32 aesCtrSz;   /* CRYPTMSTRHW.BA411EAESHWCFG2                     */
    word32 hashCfg;    /* CRYPTMSTRHW.BA413HASHHWCFG                      */
    word32 rngCfg;     /* RNGCONTROL.HWCONFIG                             */
    word32 pkCfg;      /* PK.HWCONFIG, once the microcode is loaded       */
} wc_CracenHwInfo;

/* TRNG diagnostics, accumulated since init. */
typedef struct wc_CracenTrngStats {
    word32 starts;      /* TRNG (re)initialisations                        */
    word32 errors;      /* FSM error or start-up test failure recoveries    */
    word32 repFail;     /* repetition count test alarms                    */
    word32 propFail;    /* adaptive proportion test alarms                 */
    word32 ais31Prelim; /* AIS31 preliminary noise alarms                  */
    word32 ais31Alarm;  /* AIS31 noise alarms                              */
    word32 bytes;       /* bytes delivered                                 */
    word32 lastStatus;  /* last RNGCONTROL.STATUS read                     */
} wc_CracenTrngStats;

WOLFSSL_LOCAL int    wc_CracenHw_Init(void);
WOLFSSL_LOCAL void   wc_CracenHw_Cleanup(void);
WOLFSSL_LOCAL int    wc_CracenHw_GetInfo(wc_CracenHwInfo* info);

/* Hash one or more whole blocks. data is dataSz bytes, a multiple of the
 * algorithm block size (and so of 4). state, when not NULL, is the state
 * exported by a previous call. With final == 0 the exported state (stateSz
 * bytes) is written to out; with final != 0 data must already carry the
 * standard padding and the digest (outSz bytes) is written to out. */
WOLFSSL_LOCAL int    wc_CracenHw_Hash(word32 algo, const byte* state,
                         word32 stateSz, const byte* data, word32 dataSz,
                         byte* out, word32 outSz, int final);

/* AES ECB/CBC/CTR over nSegs spans, each a non-zero multiple of 16 bytes.
 * mode is one WC_CM_AES_MODE_*; iv is 16 bytes or NULL for ECB. */
WOLFSSL_LOCAL int    wc_CracenHw_AesCrypt(word32 mode, int decrypt,
                         const byte* key, word32 keySz, const byte* iv,
                         const wc_CracenSeg* segs, int nSegs);

/* AES-GCM one shot with a 96-bit IV. The computed tag (tagSz bytes, 4..16)
 * is written to tag for both directions; the caller compares on decrypt. */
WOLFSSL_LOCAL int    wc_CracenHw_AesGcm(int decrypt, const byte* key,
                         word32 keySz, const byte* iv, const byte* aad,
                         word32 aadSz, const byte* in, word32 sz, byte* out,
                         byte* tag, word32 tagSz);

/* AES-CMAC. data is dataSz whole blocks (may be 0 with final). state is the
 * 16-byte state from a previous call or NULL. With final == 0 the new state
 * is written to out (16 bytes) and dataSz must be >= 16. With final != 0 the
 * trailing tailSz bytes (1..16, or 0 only for an empty message) are
 * absorbed and the 16-byte MAC is written to out. */
WOLFSSL_LOCAL int    wc_CracenHw_AesCmac(const byte* key, word32 keySz,
                         const byte* state, const byte* data, word32 dataSz,
                         const byte* tail, word32 tailSz, byte* out,
                         int final);

/* Conditioned TRNG output. Powers the RNG module up and starts it when
 * needed, loads the conditioning key on first use, recovers from a health
 * test failure by restarting, and fails with RNG_FAILURE_E after repeated
 * failures or a stalled FIFO. */
WOLFSSL_LOCAL int    wc_CracenHw_TrngRead(byte* out, word32 sz);
/* Power the RNG module down; the next read starts it again. */
WOLFSSL_LOCAL void   wc_CracenHw_TrngOff(void);
WOLFSSL_LOCAL int    wc_CracenHw_TrngGetStats(wc_CracenTrngStats* stats);

/* Public key engine ------------------------------------------------------ */

#define WC_CRACEN_ECC_MAX_SZ 72 /* largest ECC operand the engine takes */

/* A short Weierstrass curve for the engine. All parameters are big-endian
 * sz-byte values. For a predefined curve (selCurve != 0) the engine holds
 * the parameters itself and only gx/gy are read, for the base point. */
typedef struct wc_CracenEcCurve {
    word32      sz;
    word32      selCurve;  /* WC_PK_CURVE_* or 0                           */
    int         id;        /* wolfCrypt curve id, for the host emulator     */
    const byte* p;
    const byte* n;
    const byte* gx;
    const byte* gy;
    const byte* a;
    const byte* b;
} wc_CracenEcCurve;

/* The engine runs microcode that the application supplies (it is not part of
 * wolfSSL). Until it has been loaded every PK request is declined.
 * wc_CracenHw_PkReady returns 1 once it has. */
WOLFSSL_LOCAL int    wc_CracenHw_PkLoadMicrocode(const word32* ucode,
                         word32 words);
WOLFSSL_LOCAL int    wc_CracenHw_PkReady(void);

/* R = k * P. With cm != 0 the scalar and projective coordinates are
 * randomised against side channels (costs a TRNG read). */
WOLFSSL_LOCAL int    wc_CracenHw_EccPtMul(const wc_CracenEcCurve* c,
                         const byte* k, const byte* px, const byte* py,
                         byte* rx, byte* ry, int cm);
/* 0 when P is on the curve, IS_POINT_E otherwise. */
WOLFSSL_LOCAL int    wc_CracenHw_EccPtOnCurve(const wc_CracenEcCurve* c,
                         const byte* px, const byte* py);
/* 0 when n * P is the point at infinity, ECC_INF_E otherwise. */
WOLFSSL_LOCAL int    wc_CracenHw_EccPtOrder(const wc_CracenEcCurve* c,
                         const byte* px, const byte* py);
/* ECDSA with caller-supplied nonce k and digest h (already truncated to the
 * order size); r and s are sz bytes. */
WOLFSSL_LOCAL int    wc_CracenHw_EcdsaSign(const wc_CracenEcCurve* c,
                         const byte* d, const byte* k, const byte* h,
                         byte* r, byte* s);
WOLFSSL_LOCAL int    wc_CracenHw_EcdsaVerify(const wc_CracenEcCurve* c,
                         const byte* qx, const byte* qy, const byte* r,
                         const byte* s, const byte* h, int* res);

/* out = base ^ exp mod m, all big-endian, out is modSz bytes. */
WOLFSSL_LOCAL int    wc_CracenHw_ModExp(const byte* base, word32 baseSz,
                         const byte* exp, word32 expSz, const byte* mod,
                         word32 modSz, byte* out, int cm);
/* RSA private operation with CRT parameters; out is outSz (the modulus size)
 * bytes and every operand is at most that long. */
WOLFSSL_LOCAL int    wc_CracenHw_RsaCrt(const byte* in, word32 inSz,
                         const byte* p, word32 pSz, const byte* q, word32 qSz,
                         const byte* dP, word32 dPSz, const byte* dQ,
                         word32 dQSz, const byte* qInv, word32 qInvSz,
                         byte* out, word32 outSz, int cm);

/* X25519: out = k * u, all 32-byte little-endian (k is clamped here). */
WOLFSSL_LOCAL int    wc_CracenHw_X25519(const byte* k, const byte* u,
                         byte* out);
/* Ed25519 primitives on little-endian encodings: pt = (scalar mod L) * B
 * with a 64-byte scalar; S = r + k * s mod L with 64-byte k and r; and the
 * verification of S * B == R + k * A, which returns SIG_VERIFY_E on failure. */
WOLFSSL_LOCAL int    wc_CracenHw_Ed25519PtMul(const byte* scalar64,
                         byte* pt32);
WOLFSSL_LOCAL int    wc_CracenHw_Ed25519Sign(const byte* k64,
                         const byte* r64, const byte* s32, byte* sigS32);
WOLFSSL_LOCAL int    wc_CracenHw_Ed25519Verify(const byte* k64,
                         const byte* a32, const byte* sigS32,
                         const byte* r32);

#ifdef __cplusplus
    }
#endif

#endif /* WOLFSSL_CRACEN_HW_H */
