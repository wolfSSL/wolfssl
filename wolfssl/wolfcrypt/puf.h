/* puf.h
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

/*!
    \file wolfssl/wolfcrypt/puf.h
    \brief SRAM PUF (Physically Unclonable Function) support for wolfCrypt.

    Derives device-unique cryptographic keys from the power-on state of SRAM
    memory using a configurable BCH(127,k,t) fuzzy extractor over GF(2^7) with
    HKDF key derivation.

    Configuration (override in user_settings.h or via CPPFLAGS):
      - WC_PUF_BCH_T selects the error-correction strength / BCH profile:
        t=7 (k=78), t=10 (k=64, default), t=13 (k=50), t=15 (k=36). Higher t
        corrects more bit flips per 127-bit codeword at the cost of entropy.
      - WC_PUF_NUM_CODEWORDS (default 16) trades raw SRAM footprint and helper
        data size against total derived-key entropy.

    Enrollment and reconstruction MUST use identical WC_PUF_BCH_T and
    WC_PUF_NUM_CODEWORDS (and the same hash); a mismatch silently produces a
    wrong key. See WC_PUF_PROFILE_ID and wc_PufGetParams().

    WC_PUF_HELPER_COMPACT (opt-in) stores only the parity bits of the helper
    data, shrinking it to 39-72% of the default size. It changes the stored
    format, so the default keeps the layout used by wolfSSL 5.9.2.

    Every readout passed to wc_PufReadSram() is health tested first (see
    wc_PufCheckSram, and WC_PUF_HW_MIN_PCT / WC_PUF_HW_MAX_PCT for the
    Hamming-weight band it must fall inside). A degenerate readout - all zero,
    all ones, or a repeating block - is self-consistent through the whole
    pipeline and would yield a key identical on every device, so it is
    rejected with PUF_READ_E. The SRAM region must therefore be sampled from
    reset, before .bss/.data init and before it is used as stack or heap.

    Build: ./configure --enable-puf[=small|balanced|strong|strongest]
    (auto-enables HKDF). CMake: -DWOLFSSL_PUF=yes with
    -DWOLFSSL_PUF_PROFILE=small|balanced|strong|strongest and
    -DWOLFSSL_PUF_NUM_CODEWORDS=<n>.

    For a bare-metal example (tested on NUCLEO-H563ZI), see:
    https://github.com/wolfSSL/wolfssl-examples/tree/master/puf
*/

#ifndef WOLF_CRYPT_PUF_H
#define WOLF_CRYPT_PUF_H

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_PUF

/* PUF is not a FIPS-validated algorithm. Fail loudly at compile time rather
 * than producing undefined references at link time when WOLFSSL_PUF is
 * combined with HAVE_FIPS. */
#if defined(HAVE_FIPS)
    #error "WOLFSSL_PUF is not available when HAVE_FIPS is defined"
#endif

#include <wolfssl/wolfcrypt/types.h>

#ifdef __cplusplus
    extern "C" {
#endif

/* ------------------------------------------------------------------------ *
 * Configuration knobs (override in user_settings.h or via CPPFLAGS).       *
 *                                                                          *
 * WC_PUF_NUM_CODEWORDS: number of BCH codewords. Trades SRAM footprint and *
 *   helper-data size against derived-key entropy. Default 16.              *
 * WC_PUF_BCH_T: BCH error-correction capability (bit flips corrected per   *
 *   127-bit codeword). Selects a BCH(127,k,t) profile. Supported values:   *
 *     t=7  (k=78)  smaller parity, high entropy, less correction           *
 *     t=10 (k=64)  default, wire-compatible with prior releases            *
 *     t=13 (k=50)  stronger correction for noisier SRAM                    *
 *     t=15 (k=36)  strongest supported                                     *
 *                                                                          *
 * IMPORTANT: enrollment and reconstruction MUST use identical              *
 * WC_PUF_BCH_T and WC_PUF_NUM_CODEWORDS (and the same hash). A mismatch    *
 * silently produces a wrong key. Persist WC_PUF_PROFILE_ID (or the values  *
 * from wc_PufGetParams) with the helper data and compare on reconstruct.   *
 * ------------------------------------------------------------------------ */
#ifndef WC_PUF_NUM_CODEWORDS
    #define WC_PUF_NUM_CODEWORDS  16
#endif
#ifndef WC_PUF_BCH_T
    #define WC_PUF_BCH_T          10
#endif

/* Startup health-test band for the raw readout, as a percentage of
 * WC_PUF_RAW_BITS. A readout whose Hamming weight falls outside this band is
 * not plausible SRAM power-on noise (a cleared or written region, a stuck
 * peripheral window), so wc_PufReadSram rejects it rather than deriving a
 * device-independent key from it. Widen only if the target's SRAM is known to
 * be strongly biased and that bias has been measured with wc_PufCheckSram.
 * Note the band is a percentage while the spread of a healthy readout narrows
 * as sqrt(WC_PUF_RAW_BITS): the default is ~13 sigma wide at 16 codewords but
 * only ~3.4 sigma at 1, so a build with one or two codewords should widen it
 * rather than accept the occasional false reject at boot.
 * The band does not affect the helper-data format or the derived key, so it
 * is deliberately not part of WC_PUF_PROFILE_ID. Set it through the build so
 * an application sees the same band as the library: autotools records a
 * CPPFLAGS -D in wolfssl/options.h, and CMake has
 * -DWOLFSSL_PUF_HW_MIN_PCT / -DWOLFSSL_PUF_HW_MAX_PCT. A library-only
 * user_settings.h does not carry across, so in that case take the verdict
 * from wc_PufCheckSram() rather than recomputing the band. */
#ifndef WC_PUF_HW_MIN_PCT
    #define WC_PUF_HW_MIN_PCT     35
#endif
#ifndef WC_PUF_HW_MAX_PCT
    #define WC_PUF_HW_MAX_PCT     65
#endif
#if WC_PUF_HW_MIN_PCT >= WC_PUF_HW_MAX_PCT
    #error "WC_PUF_HW_MIN_PCT must be less than WC_PUF_HW_MAX_PCT"
#endif
#if WC_PUF_HW_MIN_PCT < 1 || WC_PUF_HW_MAX_PCT > 99
    #error "WC_PUF_HW_MIN_PCT/WC_PUF_HW_MAX_PCT must be within 1..99"
#endif

/* Fixed field: GF(2^7), codeword length n = 127 */
#define WC_PUF_BCH_M          7    /* GF(2^7) */
#define WC_PUF_BCH_N        127    /* codeword length */

/* Profile ladder: WC_PUF_BCH_T -> message length k. Only valid narrow-sense
 * BCH(127) designed-distance profiles are accepted; other t values are a
 * compile error rather than a silently wrong code. */
#if   WC_PUF_BCH_T == 7
    #define WC_PUF_BCH_K     78
#elif WC_PUF_BCH_T == 10
    #define WC_PUF_BCH_K     64
#elif WC_PUF_BCH_T == 13
    #define WC_PUF_BCH_K     50
#elif WC_PUF_BCH_T == 15
    #define WC_PUF_BCH_K     36
#else
    #error "Unsupported WC_PUF_BCH_T; use 7, 10, 13, or 15 (see puf.h)"
#endif

/* Generator-polynomial degree = parity bits per codeword = n - k */
#define WC_PUF_BCH_DEG    (WC_PUF_BCH_N - WC_PUF_BCH_K)

#if WC_PUF_NUM_CODEWORDS < 1
    #error "WC_PUF_NUM_CODEWORDS must be >= 1"
#endif
/* WC_PUF_PROFILE_ID packs the codeword count into a 12-bit field; bound it so
 * the fingerprint stays unique (and representable) for every valid build. Note
 * this is a field-width limit, not a recommendation: wc_PufCtx embeds rawSram,
 * helperData and stableBits by value, so it grows ~30 bytes per codeword and
 * large counts are impractical on the small-RAM targets this module targets. */
#if WC_PUF_NUM_CODEWORDS > 4095
    #error "WC_PUF_NUM_CODEWORDS must be <= 4095 (WC_PUF_PROFILE_ID field)"
#endif

/* Per-codeword byte sizes */
#define WC_PUF_CW_BYTES     ((WC_PUF_BCH_N   + 7) / 8)  /* 16 for n=127 */
#define WC_PUF_MSG_BYTES    ((WC_PUF_BCH_K   + 7) / 8)
#define WC_PUF_PARITY_BYTES ((WC_PUF_BCH_DEG + 7) / 8)

/* Raw SRAM readout: 128-bit stride per codeword (n=127 fits in 128 bits) */
#define WC_PUF_RAW_STRIDE_BITS   128
#define WC_PUF_RAW_STRIDE_BYTES  (WC_PUF_RAW_STRIDE_BITS / 8)
#define WC_PUF_RAW_BITS    (WC_PUF_NUM_CODEWORDS * WC_PUF_RAW_STRIDE_BITS)
#define WC_PUF_RAW_BYTES   (WC_PUF_RAW_BITS / 8)

/* One codeword per stride, so the readout health test can walk the buffer in
 * WC_PUF_CW_BYTES blocks. Every shipped profile pins n = 127, which is what
 * makes the two equal. Divergence in either direction is a build failure: a
 * larger codeword would read past the caller's region, a smaller one would
 * leave the tail of every block untested. */
#if WC_PUF_CW_BYTES != WC_PUF_RAW_STRIDE_BYTES
    #error "WC_PUF_CW_BYTES must equal the raw readout stride"
#endif

/* The band test compares ones * 100 against WC_PUF_RAW_BITS * pct in word32
 * arithmetic. The codeword cap above keeps both sides far inside that range
 * (4095 codewords -> 524160 bits -> 52416000), but pin the bound so raising
 * the cap fails the build here rather than silently wrapping the check. */
#if WC_PUF_RAW_BITS > (0xFFFFFFFFU / 100U)
    #error "WC_PUF_RAW_BITS too large for the health-test band arithmetic"
#endif

/* Reconstructed stable bits: k message bits per codeword, bit-packed */
#define WC_PUF_STABLE_BITS  (WC_PUF_NUM_CODEWORDS * WC_PUF_BCH_K)
#define WC_PUF_STABLE_BYTES ((WC_PUF_STABLE_BITS + 7) / 8)

/* Helper data, bit-packed. Only the (n - k) parity bits per codeword carry
 * information: helper = raw XOR encoded-codeword, and the systematic message
 * part of the codeword is a verbatim copy of the raw bits it came from, so the
 * leading k bits are identically zero. Size OTP/flash for that, not for n.
 *
 * WC_PUF_HELPER_COMPACT stores only the parity region. It changes the stored
 * format, so it is opt-in: the default layout stays compatible with helper
 * data enrolled by wolfSSL 5.9.2. The choice is encoded in
 * WC_PUF_PROFILE_ID so a mismatch is detectable. */
#ifdef WC_PUF_HELPER_COMPACT
    #define WC_PUF_HELPER_OFF  WC_PUF_BCH_K    /* first codeword bit stored */
    #define WC_PUF_HELPER_LEN  WC_PUF_BCH_DEG  /* bits stored per codeword */
    #define WC_PUF_HELPER_ID   1
#else
    #define WC_PUF_HELPER_OFF  0
    #define WC_PUF_HELPER_LEN  WC_PUF_BCH_N
    #define WC_PUF_HELPER_ID   0
#endif
#define WC_PUF_HELPER_BITS  (WC_PUF_NUM_CODEWORDS * WC_PUF_HELPER_LEN)
#define WC_PUF_HELPER_BYTES ((WC_PUF_HELPER_BITS + 7) / 8)

/* Recommended/default derived key size (HKDF output length is selectable) */
#define WC_PUF_KEY_SZ         32   /* 256-bit derived key */

/* Identity hash size (SHA-256 or SHA3-256 with WC_PUF_SHA3) */
#define WC_PUF_ID_SZ          32

/* Hash-selection bit for the profile fingerprint (0 = SHA-256, 1 = SHA3-256).
 * A device enrolled and reconstructed with different hashes yields a silently
 * wrong key, so the hash must be part of the fingerprint. */
#ifdef WC_PUF_SHA3
    #define WC_PUF_HASH_ID 1
#else
    #define WC_PUF_HASH_ID 0
#endif

/* Compact profile fingerprint the application can persist next to its helper
 * data and compare before reconstruction to detect a build mismatch. Packs
 * (hash, helper format, m, t, num_codewords); n is fixed at 127 and k is
 * fully determined by t, so neither needs its own field. Layout:
 *   bit  31     hash select (0 = SHA-256, 1 = SHA3-256)
 *   bit  30     helper format (0 = full codeword, 1 = compact parity-only)
 *   bits 27-29  m (GF exponent)
 *   bits 19-26  t (error-correction capability)
 *   bits 12-18  reserved
 *   bits 0-11   codeword count
 * This macro necessarily reflects the INCLUDING APPLICATION's build; use
 * wc_PufGetProfileId() to read what the library itself was compiled with. */
#define WC_PUF_PROFILE_ID \
    (((word32)WC_PUF_HASH_ID   << 31) | \
     ((word32)WC_PUF_HELPER_ID << 30) | \
     ((word32)WC_PUF_BCH_M     << 27) | \
     ((word32)WC_PUF_BCH_T     << 19) | \
     ((word32)(WC_PUF_NUM_CODEWORDS) & 0xFFFU))

/* Flags for wc_PufCtx.flags */
#define WC_PUF_FLAG_ENROLLED  0x01
#define WC_PUF_FLAG_READY     0x02
#define WC_PUF_FLAG_SRAM_SET  0x04

typedef struct wc_PufCtx {
    byte  rawSram[WC_PUF_RAW_BYTES];         /* raw SRAM readout */
    byte  helperData[WC_PUF_HELPER_BYTES];   /* enrollment helper data */
    byte  stableBits[WC_PUF_STABLE_BYTES];   /* reconstructed stable bits */
    byte  identity[WC_PUF_ID_SZ];            /* device identity hash */
    word32 flags;

#ifdef WOLFSSL_PUF_TEST
    word32 testDataSet;                      /* flag: test data was injected */
#endif
} wc_PufCtx;

WOLFSSL_API int wc_PufInit(wc_PufCtx* ctx);
WOLFSSL_API int wc_PufReadSram(wc_PufCtx* ctx, const byte* sramAddr,
                               word32 sramSz);
WOLFSSL_API int wc_PufCheckSram(const byte* sramAddr, word32 sramSz,
                                word32* onesCount);
WOLFSSL_API int wc_PufEnroll(wc_PufCtx* ctx);
WOLFSSL_API int wc_PufReconstruct(wc_PufCtx* ctx, const byte* helperData,
                                  word32 helperSz);
WOLFSSL_API int wc_PufDeriveKey(wc_PufCtx* ctx, const byte* info, word32 infoSz,
                                byte* key, word32 keySz);
WOLFSSL_API int wc_PufGetIdentity(wc_PufCtx* ctx, byte* id, word32 idSz);
WOLFSSL_API int wc_PufGetParams(int* m, int* n, int* k, int* t,
                                int* numCodewords);
WOLFSSL_API word32 wc_PufGetProfileId(void);
WOLFSSL_API int wc_PufGetHelperData(wc_PufCtx* ctx, byte* helper,
                                    word32 helperSz);
WOLFSSL_API int wc_PufReconstructEx(wc_PufCtx* ctx, const byte* helperData,
                                    word32 helperSz, word32 profileId);
WOLFSSL_API int wc_PufZeroize(wc_PufCtx* ctx);

#ifdef WOLFSSL_PUF_TEST
WOLFSSL_API int wc_PufSetTestData(wc_PufCtx* ctx, const byte* data, word32 sz);
#endif

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFSSL_PUF */

#endif /* WOLF_CRYPT_PUF_H */
