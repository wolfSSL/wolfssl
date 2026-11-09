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
} wc_CracenHwInfo;

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

WOLFSSL_LOCAL int    wc_CracenHw_TrngRead(byte* out, word32 sz);

#ifdef __cplusplus
    }
#endif

#endif /* WOLFSSL_CRACEN_HW_H */
