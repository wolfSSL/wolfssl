/* puf.c
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


#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#ifdef WOLFSSL_PUF

/* Currently only SRAM PUF is implemented. Other PUF types (ring-oscillator,
 * arbiter) may be added in the future with their own guard macros. */
#if !defined(WOLFSSL_PUF_SRAM)
    #define WOLFSSL_PUF_SRAM
#endif

/* PUF is not a FIPS-validated algorithm. The combination WOLFSSL_PUF +
 * HAVE_FIPS is rejected at compile time by puf.h, so no per-translation-unit
 * gate is needed here. */

#include <wolfssl/wolfcrypt/puf.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hash.h>

#ifdef HAVE_HKDF
    #include <wolfssl/wolfcrypt/hmac.h>
#endif

/* Hash algorithm selection: SHA3-256 or SHA-256 (default) */
#ifdef WC_PUF_SHA3
    #if !defined(WOLFSSL_SHA3)
        #error "WC_PUF_SHA3 requires WOLFSSL_SHA3 to be enabled"
    #endif
    #include <wolfssl/wolfcrypt/sha3.h>
    #define WC_PUF_HASH_TYPE  WC_SHA3_256
    #define wc_PufHashDirect  wc_Sha3_256Hash
#else
    #ifdef NO_SHA256
        #error "WOLFSSL_PUF requires SHA-256 or WC_PUF_SHA3"
    #endif
    #define WC_PUF_HASH_TYPE  WC_SHA256
    #define wc_PufHashDirect  wc_Sha256Hash
#endif

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/* ========================================================================== */
/* BCH(127,64,t=10) codec over GF(2^7)                                       */
/* ========================================================================== */

/* GF(2^7) arithmetic with primitive polynomial p(x) = x^7 + x^3 + 1 (0x89) */
#define GF_M      7
#define GF_SIZE   (1 << GF_M)   /* 128 */
#define GF_MASK   (GF_SIZE - 1) /* 127 */

/* Precomputed GF(2^7) exp table: gf_exp[i] = alpha^i for i=0..127
 * Generated with primitive polynomial 0x89 (x^7 + x^3 + 1).
 * gf_exp[127] wraps to gf_exp[0] = 1. */
static const byte gf_exp[GF_SIZE] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x09,
    0x12, 0x24, 0x48, 0x19, 0x32, 0x64, 0x41, 0x0B,
    0x16, 0x2C, 0x58, 0x39, 0x72, 0x6D, 0x53, 0x2F,
    0x5E, 0x35, 0x6A, 0x5D, 0x33, 0x66, 0x45, 0x03,
    0x06, 0x0C, 0x18, 0x30, 0x60, 0x49, 0x1B, 0x36,
    0x6C, 0x51, 0x2B, 0x56, 0x25, 0x4A, 0x1D, 0x3A,
    0x74, 0x61, 0x4B, 0x1F, 0x3E, 0x7C, 0x71, 0x6B,
    0x5F, 0x37, 0x6E, 0x55, 0x23, 0x46, 0x05, 0x0A,
    0x14, 0x28, 0x50, 0x29, 0x52, 0x2D, 0x5A, 0x3D,
    0x7A, 0x7D, 0x73, 0x6F, 0x57, 0x27, 0x4E, 0x15,
    0x2A, 0x54, 0x21, 0x42, 0x0D, 0x1A, 0x34, 0x68,
    0x59, 0x3B, 0x76, 0x65, 0x43, 0x0F, 0x1E, 0x3C,
    0x78, 0x79, 0x7B, 0x7F, 0x77, 0x67, 0x47, 0x07,
    0x0E, 0x1C, 0x38, 0x70, 0x69, 0x5B, 0x3F, 0x7E,
    0x75, 0x63, 0x4F, 0x17, 0x2E, 0x5C, 0x31, 0x62,
    0x4D, 0x13, 0x26, 0x4C, 0x11, 0x22, 0x44, 0x01
};

/* Precomputed GF(2^7) log table: gf_log[x] = log_alpha(x) for x=0..127
 * gf_log[0] is undefined (set to 0 for safety). */
static const byte gf_log[GF_SIZE] = {
    0x00, 0x00, 0x01, 0x1F, 0x02, 0x3E, 0x20, 0x67,
    0x03, 0x07, 0x3F, 0x0F, 0x21, 0x54, 0x68, 0x5D,
    0x04, 0x7C, 0x08, 0x79, 0x40, 0x4F, 0x10, 0x73,
    0x22, 0x0B, 0x55, 0x26, 0x69, 0x2E, 0x5E, 0x33,
    0x05, 0x52, 0x7D, 0x3C, 0x09, 0x2C, 0x7A, 0x4D,
    0x41, 0x43, 0x50, 0x2A, 0x11, 0x45, 0x74, 0x17,
    0x23, 0x76, 0x0C, 0x1C, 0x56, 0x19, 0x27, 0x39,
    0x6A, 0x13, 0x2F, 0x59, 0x5F, 0x47, 0x34, 0x6E,
    0x06, 0x0E, 0x53, 0x5C, 0x7E, 0x1E, 0x3D, 0x66,
    0x0A, 0x25, 0x2D, 0x32, 0x7B, 0x78, 0x4E, 0x72,
    0x42, 0x29, 0x44, 0x16, 0x51, 0x3B, 0x2B, 0x4C,
    0x12, 0x58, 0x46, 0x6D, 0x75, 0x1B, 0x18, 0x38,
    0x24, 0x31, 0x77, 0x71, 0x0D, 0x5B, 0x1D, 0x65,
    0x57, 0x6C, 0x1A, 0x37, 0x28, 0x15, 0x3A, 0x4B,
    0x6B, 0x36, 0x14, 0x4A, 0x30, 0x70, 0x5A, 0x64,
    0x60, 0x61, 0x48, 0x62, 0x35, 0x49, 0x6F, 0x63
};

/* GF multiplication */
static WC_INLINE byte gf_mul(byte a, byte b)
{
    if (a == 0 || b == 0)
        return 0;
    return gf_exp[(gf_log[a] + gf_log[b]) % GF_MASK];
}

/* GF inverse */
static WC_INLINE byte gf_inv(byte a)
{
    if (a == 0)
        return 0;
    return gf_exp[GF_MASK - gf_log[a]];
}

/* ---- BCH syndrome computation ---- */

/* Evaluate syndrome: S_root = c(alpha^root) where codeword bits are packed
 * MSB-first. Bit at position j in the byte array corresponds to the
 * coefficient of x^(N-1-j) in the codeword polynomial, so we evaluate
 * using alpha^(root*(N-1-j)) to correctly compute c(alpha^root). */
static byte bch_syndrome_eval(const byte* codeword, int root)
{
    byte s = 0;
    int j;

    for (j = 0; j < WC_PUF_BCH_N; j++) {
        int byteIdx = j / 8;
        int bitIdx  = 7 - (j % 8);

        if (codeword[byteIdx] & (1 << bitIdx)) {
            /* coefficient of x^(N-1-j), evaluated at alpha^root */
            s ^= gf_exp[(root * (WC_PUF_BCH_N - 1 - j)) % GF_MASK];
        }
    }
    return s;
}

/* Compute 2t syndromes S[1..2t] */
static void bch_syndromes(const byte* codeword, byte* syndromes)
{
    int i;
    for (i = 1; i <= 2 * WC_PUF_BCH_T; i++) {
        syndromes[i] = bch_syndrome_eval(codeword, i);
    }
}

/* ---- Berlekamp-Massey algorithm ---- */

/* Find error locator polynomial sigma(x) from syndromes.
 * sigma[] has degree <= t, coefficients in GF(2^7).
 * Returns degree of sigma, or -1 on failure. */
static int bch_berlekamp_massey(const byte* syndromes, byte* sigma)
{
    byte C[WC_PUF_BCH_T + 1];  /* current polynomial */
    byte B[WC_PUF_BCH_T + 1];  /* previous polynomial */
    byte T[WC_PUF_BCH_T + 1];  /* temp */
    int L = 0;                  /* current length */
    int m = 1;                  /* shift counter */
    byte b = 1;                 /* previous discrepancy */
    int n, i, degC;

    XMEMSET(C, 0, sizeof(C));
    XMEMSET(B, 0, sizeof(B));
    C[0] = 1;
    B[0] = 1;

    for (n = 0; n < 2 * WC_PUF_BCH_T; n++) {
        /* compute discrepancy d */
        byte d = syndromes[n + 1];
        for (i = 1; i <= L; i++) {
            d ^= gf_mul(C[i], syndromes[n + 1 - i]);
        }

        if (d == 0) {
            m++;
        }
        else if (2 * L <= n) {
            /* update: T(x) = C(x), C(x) -= (d/b)*x^m * B(x), B=T, L=n+1-L */
            byte coeff = gf_mul(d, gf_inv(b));
            XMEMCPY(T, C, sizeof(T));
            for (i = m; i <= WC_PUF_BCH_T; i++) {
                C[i] ^= gf_mul(coeff, B[i - m]);
            }
            XMEMCPY(B, T, sizeof(B));
            L = n + 1 - L;
            b = d;
            m = 1;
        }
        else {
            /* C(x) -= (d/b)*x^m * B(x) */
            byte coeff = gf_mul(d, gf_inv(b));
            for (i = m; i <= WC_PUF_BCH_T; i++) {
                C[i] ^= gf_mul(coeff, B[i - m]);
            }
            m++;
        }
    }

    XMEMCPY(sigma, C, (WC_PUF_BCH_T + 1));

    /* find degree */
    degC = 0;
    for (i = WC_PUF_BCH_T; i >= 0; i--) {
        if (sigma[i] != 0) {
            degC = i;
            break;
        }
    }

    if (degC > WC_PUF_BCH_T)
        return -1;

    return degC;
}

/* ---- Chien search: find error locations ---- */

/* Evaluate sigma at alpha^(-j) for j=0..126. Returns number of roots found.
 * Error positions stored in errPos[] as byte-scan positions (MSB-first).
 * Chien search root j maps to bit position (N-1-j) to match the MSB-first
 * codeword layout used by the syndrome computation. */
static int bch_chien_search(const byte* sigma, int deg, int* errPos)
{
    int count = 0;
    int j;

    for (j = 0; j < WC_PUF_BCH_N; j++) {
        byte val = 0;
        int i;
        for (i = 0; i <= deg; i++) {
            if (sigma[i] != 0) {
                /* sigma[i] * alpha^(-i*j) */
                int exp_val = (GF_MASK - ((i * j) % GF_MASK)) % GF_MASK;
                val ^= gf_mul(sigma[i], gf_exp[exp_val]);
            }
        }
        if (val == 0) {
            if (count >= WC_PUF_BCH_T)
                return -1;  /* too many roots, protect errPos[] bounds */
            errPos[count] = WC_PUF_BCH_N - 1 - j;
            count++;
        }
    }

    return count;
}

/* ---- BCH encode: compute parity for 64-bit message ---- */

/* Generator polynomial for BCH(127,64,t=10) over GF(2).
 * This is the product of minimal polynomials of alpha^1..alpha^(2t).
 * Degree = n - k = 63. Stored as 64-bit value (coefficients mod 2).
 * g(x) = GCD of min polys of consecutive roots. Precomputed. */

/* We store g(x) as 8 bytes, MSB first, degree-63 coefficient in bit 63.
 * The leading coefficient (x^63) is implicit. */
static const byte bch_genpoly[8] = {
    0x21, 0xAB, 0x81, 0x5B, 0xC7, 0xEC, 0x80, 0x25
};

/* Encode 64-bit message into 127-bit codeword.
 * msg: 8 bytes (64 bits), output: 16 bytes (127 bits, MSB aligned).
 * Systematic encoding: codeword = [msg(64) | parity(63)]. */
static void bch_encode(const byte* msg, byte* codeword)
{
    byte shift_reg[8]; /* 63-bit shift register for parity */
    int i, j;

    XMEMSET(shift_reg, 0, sizeof(shift_reg));

    /* Process each of the 64 message bits */
    for (i = 0; i < WC_PUF_BCH_K; i++) {
        int byteIdx = i / 8;
        int bitIdx  = 7 - (i % 8);
        byte msgBit = (msg[byteIdx] >> bitIdx) & 1;

        /* feedback = msgBit XOR MSB of shift register */
        byte fb = msgBit ^ ((shift_reg[0] >> 6) & 1);

        /* shift register left by 1 */
        for (j = 0; j < 7; j++) {
            shift_reg[j] = (byte)((shift_reg[j] << 1) |
                                  (shift_reg[j + 1] >> 7));
        }
        shift_reg[7] = (byte)(shift_reg[7] << 1);
        /* keep the register at exactly 63 bits - bit 7 of byte 0 is unused */
        shift_reg[0] &= 0x7F;

        /* XOR with generator if feedback is 1 */
        if (fb) {
            for (j = 0; j < 8; j++) {
                shift_reg[j] ^= bch_genpoly[j];
            }
            /* generator polynomial bit 7 is 0; mask defensively in case it
             * ever changes so the unused slot can never affect parity */
            shift_reg[0] &= 0x7F;
        }
    }

    /* Build codeword: [msg(64 bits) | parity(63 bits)] = 127 bits */
    XMEMSET(codeword, 0, 16);
    XMEMCPY(codeword, msg, 8);  /* message in first 64 bits */

    /* parity: bits 64..126 from shift_reg bits 0..62 */
    /* shift_reg holds 63 bits in bits [6..0] of byte 0, then bytes 1..7 */
    /* We need to place these starting at bit position 64 in codeword */
    for (i = 0; i < 63; i++) {
        int srcByte;
        int srcBit;

        /* shift_reg MSB is bit 6 of byte 0 */
        if (i < 7) {
            srcByte = 0;
            srcBit = 6 - i;
        }
        else {
            srcByte = (i - 7) / 8 + 1;
            srcBit = 7 - ((i - 7) % 8);
        }

        if (shift_reg[srcByte] & (1 << srcBit)) {
            int dstPos = 64 + i;
            int dstByte = dstPos / 8;
            int dstBit  = 7 - (dstPos % 8);
            codeword[dstByte] |= (byte)(1 << dstBit);
        }
    }
}

/* ---- BCH decode ---- */

/* Decode 127-bit codeword, correct up to t=10 errors.
 * Extracts 64-bit message into msg (8 bytes).
 * Returns 0 on success, negative on uncorrectable error. */
static int bch_decode(byte* codeword, byte* msg)
{
    byte syndr[2 * WC_PUF_BCH_T + 1];
    byte sigma[WC_PUF_BCH_T + 1];
    int errPos[WC_PUF_BCH_T];
    int deg, numErr;
    int i;
    int allZero = 1;

    bch_syndromes(codeword, syndr);

    /* check if all syndromes are zero (no errors) */
    for (i = 1; i <= 2 * WC_PUF_BCH_T; i++) {
        if (syndr[i] != 0) {
            allZero = 0;
            break;
        }
    }

    if (allZero) {
        /* no errors, extract message directly */
        XMEMCPY(msg, codeword, 8);
        return 0;
    }

    deg = bch_berlekamp_massey(syndr, sigma);
    if (deg < 0)
        return PUF_RECONSTRUCT_E;

    numErr = bch_chien_search(sigma, deg, errPos);
    if (numErr != deg)
        return PUF_RECONSTRUCT_E;  /* number of roots must match degree */

    /* correct errors by flipping bits */
    for (i = 0; i < numErr; i++) {
        int pos = errPos[i];
        if (pos < WC_PUF_BCH_N) {
            int byteIdx = pos / 8;
            int bitIdx  = 7 - (pos % 8);
            codeword[byteIdx] ^= (byte)(1 << bitIdx);
        }
    }

    /* verify the correction actually fixed the codeword by recomputing
     * syndromes - guards against silent miscorrection when the input has
     * more than t errors and the decoder is led to a different valid
     * codeword (which would otherwise produce a wrong key/identity) */
    bch_syndromes(codeword, syndr);
    for (i = 1; i <= 2 * WC_PUF_BCH_T; i++) {
        if (syndr[i] != 0)
            return PUF_RECONSTRUCT_E;
    }

    /* extract message (first 64 bits) */
    XMEMCPY(msg, codeword, 8);
    return 0;
}

/* ========================================================================== */
/* PUF API                                                                    */
/* ========================================================================== */

/* Get a single bit from byte array (MSB-first bit ordering) */
static WC_INLINE byte getBit(const byte* data, int bitPos)
{
    return (data[bitPos / 8] >> (7 - (bitPos % 8))) & 1;
}

/* Set a single bit in byte array (MSB-first bit ordering) */
static WC_INLINE void setBit(byte* data, int bitPos, byte val)
{
    int byteIdx = bitPos / 8;
    int bitIdx  = 7 - (bitPos % 8);
    if (val)
        data[byteIdx] |= (byte)(1 << bitIdx);
    else
        data[byteIdx] &= (byte)~(1 << bitIdx);
}

/* Extract 127 bits from raw SRAM starting at given bit offset */
static void extractCodeword(const byte* sram, int bitOffset, byte* cw)
{
    int i;
    XMEMSET(cw, 0, 16);
    for (i = 0; i < WC_PUF_BCH_N; i++) {
        setBit(cw, i, getBit(sram, bitOffset + i));
    }
}

/* Store 127 bits into helper data at given bit offset */
static void storeCodeword(byte* helper, int bitOffset, const byte* cw)
{
    int i;
    for (i = 0; i < WC_PUF_BCH_N; i++) {
        setBit(helper, bitOffset + i, getBit(cw, i));
    }
}


int wc_PufInit(wc_PufCtx* ctx)
{
    WOLFSSL_ENTER("wc_PufInit");

    if (ctx == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(ctx, 0, sizeof(wc_PufCtx));

    return 0;
}

int wc_PufReadSram(wc_PufCtx* ctx, const byte* sramAddr, word32 sramSz)
{
    WOLFSSL_ENTER("wc_PufReadSram");

    if (ctx == NULL || sramAddr == NULL)
        return BAD_FUNC_ARG;
    if (sramSz < WC_PUF_RAW_BYTES)
        return PUF_READ_E;

#ifdef WOLFSSL_PUF_TEST
    if (ctx->testDataSet) {
        /* rawSram already populated by wc_PufSetTestData */
        ctx->flags |= WC_PUF_FLAG_SRAM_SET;
        return 0;
    }
#endif

    XMEMCPY(ctx->rawSram, sramAddr, WC_PUF_RAW_BYTES);
    ctx->flags |= WC_PUF_FLAG_SRAM_SET;
    return 0;
}

int wc_PufEnroll(wc_PufCtx* ctx)
{
    int i, ret;
    byte msg[8];    /* 64-bit message */
    byte cw[16];    /* 127-bit codeword */
    byte rawCw[16];
    byte helperCw[16];

    WOLFSSL_ENTER("wc_PufEnroll");

    if (ctx == NULL)
        return BAD_FUNC_ARG;
    if (!(ctx->flags & WC_PUF_FLAG_SRAM_SET))
        return PUF_ENROLL_E;

    XMEMSET(ctx->helperData, 0, WC_PUF_HELPER_BYTES);
    XMEMSET(ctx->stableBits, 0, WC_PUF_STABLE_BYTES);

    for (i = 0; i < WC_PUF_NUM_CODEWORDS; i++) {
        /* extract 64 message bits from raw SRAM */
        int bitOff = i * 128;  /* 128-bit stride for alignment */
        int j;
        XMEMSET(msg, 0, sizeof(msg));
        for (j = 0; j < WC_PUF_BCH_K; j++) {
            setBit(msg, j, getBit(ctx->rawSram, bitOff + j));
        }

        /* save stable bits */
        XMEMCPY(ctx->stableBits + i * 8, msg, 8);

        /* encode message into BCH codeword */
        bch_encode(msg, cw);

        /* helper = raw XOR codeword (mask) */
        extractCodeword(ctx->rawSram, bitOff, rawCw);
        XMEMSET(helperCw, 0, 16);
        for (j = 0; j < 16; j++) {
            helperCw[j] = rawCw[j] ^ cw[j];
        }
        storeCodeword(ctx->helperData, i * WC_PUF_BCH_N, helperCw);
    }

    /* compute identity = SHA-256(stableBits) */
    ret = wc_PufHashDirect(ctx->stableBits, WC_PUF_STABLE_BYTES, ctx->identity);

    /* zeroize sensitive stack buffers */
    ForceZero(msg, sizeof(msg));
    ForceZero(cw, sizeof(cw));
    ForceZero(rawCw, sizeof(rawCw));
    ForceZero(helperCw, sizeof(helperCw));

    if (ret != 0)
        return PUF_ENROLL_E;

    ctx->flags |= WC_PUF_FLAG_ENROLLED | WC_PUF_FLAG_READY;
    return 0;
}

int wc_PufReconstruct(wc_PufCtx* ctx, const byte* helperData, word32 helperSz)
{
    int i, ret;
    byte rawCw[16];
    byte helperCw[16];
    byte noisyCw[16];
    byte msg[8];

    WOLFSSL_ENTER("wc_PufReconstruct");

    if (ctx == NULL || helperData == NULL)
        return BAD_FUNC_ARG;
    if (helperSz < WC_PUF_HELPER_BYTES)
        return PUF_RECONSTRUCT_E;
    if (!(ctx->flags & WC_PUF_FLAG_SRAM_SET))
        return PUF_RECONSTRUCT_E;

    XMEMSET(ctx->stableBits, 0, WC_PUF_STABLE_BYTES);

    for (i = 0; i < WC_PUF_NUM_CODEWORDS; i++) {
        int bitOff = i * 128;
        int j;

        /* get raw SRAM bits for this codeword */
        extractCodeword(ctx->rawSram, bitOff, rawCw);

        /* get helper data for this codeword */
        XMEMSET(helperCw, 0, 16);
        for (j = 0; j < WC_PUF_BCH_N; j++) {
            setBit(helperCw, j, getBit(helperData, i * WC_PUF_BCH_N + j));
        }

        /* noisy codeword = raw XOR helper */
        for (j = 0; j < 16; j++) {
            noisyCw[j] = rawCw[j] ^ helperCw[j];
        }

        /* BCH decode to recover original message */
        ret = bch_decode(noisyCw, msg);
        if (ret != 0) {
            ForceZero(rawCw, sizeof(rawCw));
            ForceZero(helperCw, sizeof(helperCw));
            ForceZero(noisyCw, sizeof(noisyCw));
            ForceZero(msg, sizeof(msg));
            ForceZero(ctx->stableBits, WC_PUF_STABLE_BYTES);
            ctx->flags &= (word32)~WC_PUF_FLAG_READY;
            return PUF_RECONSTRUCT_E;
        }

        XMEMCPY(ctx->stableBits + i * 8, msg, 8);
    }

    /* compute identity */
    ret = wc_PufHashDirect(ctx->stableBits, WC_PUF_STABLE_BYTES, ctx->identity);

    /* zeroize sensitive stack buffers */
    ForceZero(rawCw, sizeof(rawCw));
    ForceZero(helperCw, sizeof(helperCw));
    ForceZero(noisyCw, sizeof(noisyCw));
    ForceZero(msg, sizeof(msg));

    if (ret != 0)
        return PUF_RECONSTRUCT_E;

    ctx->flags |= WC_PUF_FLAG_READY;
    return 0;
}

int wc_PufDeriveKey(wc_PufCtx* ctx, const byte* info, word32 infoSz,
                    byte* key, word32 keySz)
{
    WOLFSSL_ENTER("wc_PufDeriveKey");

    if (ctx == NULL || key == NULL)
        return BAD_FUNC_ARG;
    if (!(ctx->flags & WC_PUF_FLAG_READY))
        return PUF_DERIVE_KEY_E;
    if (keySz == 0)
        return BAD_FUNC_ARG;

    /* Documented contract: info may be NULL. Normalize so callers can pass
     * (NULL, anything) without forwarding an invalid pointer/length pair to
     * HKDF. */
    if (info == NULL)
        infoSz = 0;

#ifdef HAVE_HKDF
    {
        /* HKDF with stable bits as IKM, identity as salt */
        int ret;
        ret = wc_HKDF(WC_PUF_HASH_TYPE,
                       ctx->stableBits, WC_PUF_STABLE_BYTES,
                       ctx->identity, WC_PUF_ID_SZ,
                       info, infoSz,
                       key, keySz);
        if (ret != 0)
            return PUF_DERIVE_KEY_E;

        return 0;
    }
#else
    (void)info;
    (void)infoSz;
    return PUF_DERIVE_KEY_E;
#endif
}

int wc_PufGetIdentity(wc_PufCtx* ctx, byte* id, word32 idSz)
{
    WOLFSSL_ENTER("wc_PufGetIdentity");

    if (ctx == NULL || id == NULL)
        return BAD_FUNC_ARG;
    if (!(ctx->flags & WC_PUF_FLAG_READY))
        return PUF_IDENTITY_E;
    if (idSz < WC_PUF_ID_SZ)
        return PUF_IDENTITY_E;

    XMEMCPY(id, ctx->identity, WC_PUF_ID_SZ);
    return 0;
}

int wc_PufZeroize(wc_PufCtx* ctx)
{
    WOLFSSL_ENTER("wc_PufZeroize");

    if (ctx == NULL)
        return BAD_FUNC_ARG;

    ForceZero(ctx, sizeof(wc_PufCtx));
    return 0;
}

#ifdef WOLFSSL_PUF_TEST
int wc_PufSetTestData(wc_PufCtx* ctx, const byte* data, word32 sz)
{
    WOLFSSL_ENTER("wc_PufSetTestData");

    if (ctx == NULL || data == NULL)
        return BAD_FUNC_ARG;
    if (sz < WC_PUF_RAW_BYTES)
        return PUF_READ_E;

    /* Copy test data directly into rawSram and set flag */
    XMEMCPY(ctx->rawSram, data, WC_PUF_RAW_BYTES);
    ctx->testDataSet = 1;
    ctx->flags |= WC_PUF_FLAG_SRAM_SET;
    return 0;
}
#endif /* WOLFSSL_PUF_TEST */

#endif /* WOLFSSL_PUF */
