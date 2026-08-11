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

/* ---- Bit helpers (MSB-first bit ordering within a byte array) ---- */

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

/* Copy nbits (MSB-first) from the front of src into dst. Copies the whole-byte
 * prefix with a single memcpy and bit-loops only the < 8 trailing bits, so a
 * byte-aligned length (e.g. t=10 k=64) is byte-for-byte a plain memcpy. */
static void copyBits(byte* dst, const byte* src, int nbits)
{
    int full = nbits / 8;
    int i;

    if (full > 0)
        XMEMCPY(dst, src, (word32)full);
    if ((nbits & 7) != 0) {
        dst[full] = 0;
        for (i = full * 8; i < nbits; i++)
            setBit(dst, i, getBit(src, i));
    }
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

/* Compute 2t syndromes S[1..2t]. The codeword has GF(2) coefficients, so
 * c(x)^2 = c(x^2) and therefore S_2i = S_i^2: only the t odd-index syndromes
 * need a full evaluation pass, each even one is a single squaring. Syndromes
 * dominate reconstruct and are computed twice per codeword (the second time
 * for the post-correction recheck), so this roughly halves that cost. */
static void bch_syndromes(const byte* codeword, byte* syndromes)
{
    byte s;
    int i;

    for (i = 1; i <= 2 * WC_PUF_BCH_T; i += 2) {
        syndromes[i] = bch_syndrome_eval(codeword, i);
    }
    /* ascending, so S[i/2] is always already computed when S[i] is filled */
    for (i = 2; i <= 2 * WC_PUF_BCH_T; i += 2) {
        s = syndromes[i / 2];
        syndromes[i] = (s == 0) ? (byte)0 :
                       gf_exp[(2 * (int)gf_log[s]) % GF_MASK];
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

/* ---- BCH encode: compute parity for a k-bit message ---- */

/* Generator polynomial for the selected BCH(127,k,t) profile over GF(2).
 * g(x) is the product (lcm) of the minimal polynomials of alpha^1..alpha^(2t);
 * its degree is n - k. The bytes below are generated and validated by
 * scripts/puf_bch_genpoly.py (which reproduces the t=10 constant exactly as
 * an oracle before emitting the others). Do NOT hand-edit: a single wrong
 * bit silently corrupts every derived key.
 *
 * Storage layout: a big-endian integer of WC_PUF_PARITY_BYTES bytes whose
 * bit i (LSB = 0) is coefficient g_i for i in [0, deg). The leading
 * coefficient g_deg (== 1) is implicit; any bits above deg are zero. */
#if   WC_PUF_BCH_T == 7
    static const byte bch_genpoly[WC_PUF_PARITY_BYTES] = {
        0x00, 0xC9, 0x80, 0x11, 0xD8, 0xB0, 0x4D
    };
    #define BCH_GENPOLY_DEG 49
#elif WC_PUF_BCH_T == 10
    static const byte bch_genpoly[WC_PUF_PARITY_BYTES] = {
        0x21, 0xAB, 0x81, 0x5B, 0xC7, 0xEC, 0x80, 0x25
    };
    #define BCH_GENPOLY_DEG 63
#elif WC_PUF_BCH_T == 13
    static const byte bch_genpoly[WC_PUF_PARITY_BYTES] = {
        0x0C, 0x93, 0x52, 0xAA, 0x6C, 0xC0, 0x54, 0x46, 0x83, 0x11
    };
    #define BCH_GENPOLY_DEG 77
#elif WC_PUF_BCH_T == 15
    static const byte bch_genpoly[WC_PUF_PARITY_BYTES] = {
        0x04, 0xCC, 0x3C, 0xDB, 0x54, 0x87, 0xA2, 0x4F, 0xA5, 0xF3, 0xA3, 0xDD
    };
    #define BCH_GENPOLY_DEG 91
#else
    #error "No generator polynomial for the selected WC_PUF_BCH_T"
#endif

/* Cross-check the shipped polynomial degree against the derived n - k. */
#if BCH_GENPOLY_DEG != WC_PUF_BCH_DEG
    #error "bch_genpoly degree does not match WC_PUF_BCH_DEG (n - k)"
#endif

/* Mask keeping only the used bits of the most-significant parity byte
 * (the register holds exactly WC_PUF_BCH_DEG bits; higher bits are unused). */
#define BCH_REG_MSB_MASK \
    ((byte)((1 << (((WC_PUF_BCH_DEG - 1) & 7) + 1)) - 1))

/* Read big-endian bit b (LSB = 0) from a parity-register byte array. */
static WC_INLINE byte regGetBit(const byte* reg, int b)
{
    return (reg[WC_PUF_PARITY_BYTES - 1 - (b / 8)] >> (b % 8)) & 1;
}

/* Encode a k-bit message into a 127-bit codeword.
 * msg: WC_PUF_MSG_BYTES bytes (k bits, MSB-first), output: WC_PUF_CW_BYTES
 * bytes (127 bits, MSB aligned). Systematic: codeword = [msg(k) | parity(deg)].
 *
 * The parity register is a big-endian integer of WC_PUF_PARITY_BYTES bytes
 * holding WC_PUF_BCH_DEG bits; this generalizes the fixed degree-63 LFSR and
 * reproduces the t=10 output byte-for-byte. */
static void bch_encode(const byte* msg, byte* codeword)
{
    byte shift_reg[WC_PUF_PARITY_BYTES];
    int i, j;

    XMEMSET(shift_reg, 0, sizeof(shift_reg));

    /* Process each of the k message bits (MSB-first) */
    for (i = 0; i < WC_PUF_BCH_K; i++) {
        byte msgBit = getBit(msg, i);

        /* feedback = msgBit XOR MSB of shift register (bit deg-1) */
        byte fb = msgBit ^ regGetBit(shift_reg, WC_PUF_BCH_DEG - 1);

        /* shift register left by 1 (big-endian, byte 0 most significant) */
        for (j = 0; j < WC_PUF_PARITY_BYTES - 1; j++) {
            shift_reg[j] = (byte)((shift_reg[j] << 1) |
                                  (shift_reg[j + 1] >> 7));
        }
        shift_reg[WC_PUF_PARITY_BYTES - 1] =
            (byte)(shift_reg[WC_PUF_PARITY_BYTES - 1] << 1);
        /* keep the register at exactly WC_PUF_BCH_DEG bits */
        shift_reg[0] &= BCH_REG_MSB_MASK;

        /* XOR with generator if feedback is 1 */
        if (fb) {
            for (j = 0; j < WC_PUF_PARITY_BYTES; j++) {
                shift_reg[j] ^= bch_genpoly[j];
            }
            /* unused high bits of g are zero; mask defensively */
            shift_reg[0] &= BCH_REG_MSB_MASK;
        }
    }

    /* Build codeword: [msg(k bits) | parity(deg bits)] = 127 bits */
    XMEMSET(codeword, 0, WC_PUF_CW_BYTES);
    for (i = 0; i < WC_PUF_BCH_K; i++) {
        setBit(codeword, i, getBit(msg, i));
    }

    /* parity: register MSB (bit deg-1) first, into codeword positions k..n-1 */
    for (i = 0; i < WC_PUF_BCH_DEG; i++) {
        setBit(codeword, WC_PUF_BCH_K + i,
               regGetBit(shift_reg, WC_PUF_BCH_DEG - 1 - i));
    }
}

/* ---- BCH decode ---- */

/* Decode 127-bit codeword, correct up to WC_PUF_BCH_T errors.
 * Extracts the k-bit message into msg (WC_PUF_MSG_BYTES bytes).
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
        copyBits(msg, codeword, WC_PUF_BCH_K);
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

    /* extract message (first k bits) */
    copyBits(msg, codeword, WC_PUF_BCH_K);
    return 0;
}

/* ========================================================================== */
/* PUF API                                                                    */
/* ========================================================================== */

/* Extract 127 bits from raw SRAM starting at given bit offset */
static void extractCodeword(const byte* sram, int bitOffset, byte* cw)
{
    int i;
    XMEMSET(cw, 0, WC_PUF_CW_BYTES);
    for (i = 0; i < WC_PUF_BCH_N; i++) {
        setBit(cw, i, getBit(sram, bitOffset + i));
    }
}

/* Store the retained region of a helper codeword into helper data at the
 * given bit offset. With WC_PUF_HELPER_COMPACT only the (n-k) parity bits are
 * kept (the leading k bits are identically zero); otherwise the full n bits
 * are stored, matching the layout shipped in 5.9.2. */
static void storeCodeword(byte* helper, int bitOffset, const byte* cw)
{
    int i;
    for (i = 0; i < WC_PUF_HELPER_LEN; i++) {
        setBit(helper, bitOffset + i, getBit(cw, WC_PUF_HELPER_OFF + i));
    }
}


/* Population count. Nibble table, not a builtin: bare-metal C89 toolchains. */
static word32 pufBitCount(const byte* buf, word32 sz)
{
    static const byte nibbleBits[16] =
        { 0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4 };
    word32 i;
    word32 count = 0;

    for (i = 0; i < sz; i++) {
        count += nibbleBits[buf[i] & 0x0F];
        count += nibbleBits[(buf[i] >> 4) & 0x0F];
    }

    return count;
}

/* Startup health test on a candidate raw SRAM readout. Constant input is
 * self-consistent through encoding, masking, decoding and HKDF, so a
 * degenerate readout would yield a key identical on every device. Reject it
 * here, at the only production boundary raw PUF material enters through
 * (wc_PufSetTestData deliberately bypasses it under WOLFSSL_PUF_TEST, so the
 * test vectors it injects are not filtered).
 *
 * Three O(WC_PUF_RAW_BYTES) checks: no block all zero or all ones, no block
 * repeating the one before it, and total Hamming weight inside the
 * WC_PUF_HW_MIN_PCT..WC_PUF_HW_MAX_PCT band. The first two false-reject real
 * SRAM with probability ~2^-127 per block; the band passes biased silicon.
 *
 * onesCount is optional. It is written whenever the size check passes -
 * including when the readout is then rejected, so bring-up code can report the
 * measured bias of a region it just had refused - and left untouched when
 * sramAddr is NULL or sramSz is short, because there is nothing to measure. */
int wc_PufCheckSram(const byte* sramAddr, word32 sramSz, word32* onesCount)
{
    const byte* slice;
    word32 ones;
    word32 i;
    int    j;
    int    allZero;
    int    allOnes;

    WOLFSSL_ENTER("wc_PufCheckSram");

    if (sramAddr == NULL)
        return BAD_FUNC_ARG;
    if (sramSz < WC_PUF_RAW_BYTES) {
        /* every other PUF_READ_E from here names its cause, and a region
         * sized for the wrong WC_PUF_NUM_CODEWORDS is the likeliest one */
        WOLFSSL_MSG("PUF: SRAM readout smaller than WC_PUF_RAW_BYTES");
        return PUF_READ_E;
    }

    ones = pufBitCount(sramAddr, WC_PUF_RAW_BYTES);
    if (onesCount != NULL)
        *onesCount = ones;

    /* one codeword per stride, pinned by the guard in puf.h, so a stride is
     * one block here */
    for (i = 0; i < (word32)WC_PUF_NUM_CODEWORDS; i++) {
        slice = sramAddr + (i * WC_PUF_RAW_STRIDE_BYTES);

        allZero = 1;
        allOnes = 1;
        for (j = 0; j < WC_PUF_RAW_STRIDE_BYTES; j++) {
            if (slice[j] != 0x00)
                allZero = 0;
            if (slice[j] != 0xFF)
                allOnes = 0;
        }
        if (allZero) {
            WOLFSSL_MSG("PUF: all-zero block in SRAM readout");
            return PUF_READ_E;
        }
        if (allOnes) {
            WOLFSSL_MSG("PUF: all-ones block in SRAM readout");
            return PUF_READ_E;
        }

        /* Previous block only: that covers what this test exists for - a
         * uniform fill, a memset, a re-read of one address. Longer-period
         * structure is not chased; a cheap startup test cannot tell it from
         * noise. */
        if (i > 0 && XMEMCMP(slice, slice - WC_PUF_RAW_STRIDE_BYTES,
                             WC_PUF_RAW_STRIDE_BYTES) == 0) {
            WOLFSSL_MSG("PUF: repeated block in SRAM readout");
            return PUF_READ_E;
        }
    }

    if (ones * 100U < (word32)WC_PUF_RAW_BITS * WC_PUF_HW_MIN_PCT) {
        WOLFSSL_MSG("PUF: SRAM readout has too few one bits");
        return PUF_READ_E;
    }
    if (ones * 100U > (word32)WC_PUF_RAW_BITS * WC_PUF_HW_MAX_PCT) {
        WOLFSSL_MSG("PUF: SRAM readout has too many one bits");
        return PUF_READ_E;
    }

    return 0;
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
    int ret;

    WOLFSSL_ENTER("wc_PufReadSram");

    if (ctx == NULL)
        return BAD_FUNC_ARG;

    /* Any failed read invalidates the readout the context was holding, so the
     * flag goes down before every path that can fail, bad arguments included.
     * Otherwise a read that returns an error still leaves wc_PufEnroll and
     * wc_PufReconstruct running on whatever an earlier call had accepted. */
    ctx->flags &= (word32)~WC_PUF_FLAG_SRAM_SET;

    if (sramAddr == NULL)
        return BAD_FUNC_ARG;

    /* must be checked here too: it guards the full-size XMEMCPY below, and
     * this is the path an integrator hits, so it names its cause as well */
    if (sramSz < WC_PUF_RAW_BYTES) {
        WOLFSSL_MSG("PUF: SRAM readout smaller than WC_PUF_RAW_BYTES");
        return PUF_READ_E;
    }

#ifdef WOLFSSL_PUF_TEST
    if (ctx->testDataSet) {
        /* rawSram already populated by wc_PufSetTestData */
        ctx->flags |= WC_PUF_FLAG_SRAM_SET;
        return 0;
    }
#endif

    /* Health test the copy that will actually be used, not the caller's
     * buffer: the region is volatile by construction, so the bytes read for
     * the copy are not guaranteed to be the bytes the test saw.
     *
     * WC_PUF_FLAG_SRAM_SET is already down (above), so the context does not
     * look like it holds a validated readout for the window in which rawSram
     * holds unvalidated bytes; it goes back up only once the test passes. A
     * rejected readout is scrubbed rather than left resident, and wc_PufEnroll
     * and wc_PufReconstruct then refuse to run on the context. Output already
     * derived from a readout that did pass - identity, helper data, a derived
     * key - is unaffected and stays available. */
    XMEMCPY(ctx->rawSram, sramAddr, WC_PUF_RAW_BYTES);
    ret = wc_PufCheckSram(ctx->rawSram, WC_PUF_RAW_BYTES, NULL);
    if (ret != 0) {
        /* only this path scrubs: it is the one that copied unvalidated bytes
         * in. The paths that fail before the copy leave the previously
         * accepted readout in place, unreachable behind the cleared flag. */
        ForceZero(ctx->rawSram, WC_PUF_RAW_BYTES);
        return ret;
    }

    ctx->flags |= WC_PUF_FLAG_SRAM_SET;
    return 0;
}

int wc_PufEnroll(wc_PufCtx* ctx)
{
    int i, ret;
    byte msg[WC_PUF_MSG_BYTES];   /* k-bit message */
    byte cw[WC_PUF_CW_BYTES];     /* 127-bit codeword */
    byte rawCw[WC_PUF_CW_BYTES];
    byte helperCw[WC_PUF_CW_BYTES];

    WOLFSSL_ENTER("wc_PufEnroll");

    if (ctx == NULL)
        return BAD_FUNC_ARG;
    if (!(ctx->flags & WC_PUF_FLAG_SRAM_SET))
        return PUF_ENROLL_E;

    /* Register secret stack buffers at the top of scope: no early exit remains
     * below this point that bypasses the scrub. Poison first so they are
     * defined at registration. */
#ifdef WOLFSSL_CHECK_MEM_ZERO
    XMEMSET(msg, 0xff, sizeof(msg));
    XMEMSET(cw, 0xff, sizeof(cw));
    XMEMSET(rawCw, 0xff, sizeof(rawCw));
    XMEMSET(helperCw, 0xff, sizeof(helperCw));
    wc_MemZero_Add("wc_PufEnroll msg", msg, sizeof(msg));
    wc_MemZero_Add("wc_PufEnroll cw", cw, sizeof(cw));
    wc_MemZero_Add("wc_PufEnroll rawCw", rawCw, sizeof(rawCw));
    wc_MemZero_Add("wc_PufEnroll helperCw", helperCw, sizeof(helperCw));
#endif

    XMEMSET(ctx->helperData, 0, WC_PUF_HELPER_BYTES);
    XMEMSET(ctx->stableBits, 0, WC_PUF_STABLE_BYTES);

    for (i = 0; i < WC_PUF_NUM_CODEWORDS; i++) {
        /* extract k message bits from raw SRAM */
        /* one codeword per raw stride; see WC_PUF_RAW_STRIDE_BITS in puf.h */
        int bitOff = i * WC_PUF_RAW_STRIDE_BITS;
        int j;
        XMEMSET(msg, 0, sizeof(msg));
        for (j = 0; j < WC_PUF_BCH_K; j++) {
            setBit(msg, j, getBit(ctx->rawSram, bitOff + j));
        }

        /* save stable bits: k bits per codeword, bit-packed */
        for (j = 0; j < WC_PUF_BCH_K; j++) {
            setBit(ctx->stableBits, i * WC_PUF_BCH_K + j, getBit(msg, j));
        }

        /* encode message into BCH codeword */
        bch_encode(msg, cw);

        /* helper = raw XOR codeword (mask) */
        extractCodeword(ctx->rawSram, bitOff, rawCw);
        XMEMSET(helperCw, 0, WC_PUF_CW_BYTES);
        for (j = 0; j < WC_PUF_CW_BYTES; j++) {
            helperCw[j] = rawCw[j] ^ cw[j];
        }
        storeCodeword(ctx->helperData, i * WC_PUF_HELPER_LEN, helperCw);
    }

    /* compute identity = hash(stableBits) */
    ret = wc_PufHashDirect(ctx->stableBits, WC_PUF_STABLE_BYTES, ctx->identity);

    /* zeroize sensitive stack buffers */
    ForceZero(msg, sizeof(msg));
    ForceZero(cw, sizeof(cw));
    ForceZero(rawCw, sizeof(rawCw));
    ForceZero(helperCw, sizeof(helperCw));
#ifdef WOLFSSL_CHECK_MEM_ZERO
    wc_MemZero_Check(msg, sizeof(msg));
    wc_MemZero_Check(cw, sizeof(cw));
    wc_MemZero_Check(rawCw, sizeof(rawCw));
    wc_MemZero_Check(helperCw, sizeof(helperCw));
#endif

    if (ret != 0)
        return PUF_ENROLL_E;

    ctx->flags |= WC_PUF_FLAG_ENROLLED | WC_PUF_FLAG_READY;
    return 0;
}

int wc_PufReconstructEx(wc_PufCtx* ctx, const byte* helperData,
                        word32 helperSz, word32 profileId)
{
    int i, ret;
    byte rawCw[WC_PUF_CW_BYTES];
    byte helperCw[WC_PUF_CW_BYTES];
    byte noisyCw[WC_PUF_CW_BYTES];
    byte msg[WC_PUF_MSG_BYTES];

    WOLFSSL_ENTER("wc_PufReconstructEx");

    if (ctx == NULL || helperData == NULL)
        return BAD_FUNC_ARG;
    /* Reject helper data from a different build before touching it: the
     * length guard cannot catch this on its own, because helper size does not
     * depend on t in the default layout. A mismatch would otherwise decode to
     * a silently wrong key. */
    if (profileId != (word32)WC_PUF_PROFILE_ID)
        return BAD_FUNC_ARG;
    if (helperSz < WC_PUF_HELPER_BYTES)
        return PUF_RECONSTRUCT_E;
    if (!(ctx->flags & WC_PUF_FLAG_SRAM_SET))
        return PUF_RECONSTRUCT_E;

    /* Register secret stack buffers at the top of scope: no early exit remains
     * below this point that bypasses the scrub. Poison first so they are
     * defined at registration. */
#ifdef WOLFSSL_CHECK_MEM_ZERO
    XMEMSET(rawCw, 0xff, sizeof(rawCw));
    XMEMSET(helperCw, 0xff, sizeof(helperCw));
    XMEMSET(noisyCw, 0xff, sizeof(noisyCw));
    XMEMSET(msg, 0xff, sizeof(msg));
    wc_MemZero_Add("wc_PufReconstruct rawCw", rawCw, sizeof(rawCw));
    wc_MemZero_Add("wc_PufReconstruct helperCw", helperCw, sizeof(helperCw));
    wc_MemZero_Add("wc_PufReconstruct noisyCw", noisyCw, sizeof(noisyCw));
    wc_MemZero_Add("wc_PufReconstruct msg", msg, sizeof(msg));
#endif

    XMEMSET(ctx->stableBits, 0, WC_PUF_STABLE_BYTES);

    for (i = 0; i < WC_PUF_NUM_CODEWORDS; i++) {
        int bitOff = i * WC_PUF_RAW_STRIDE_BITS;
        int j;

        /* get raw SRAM bits for this codeword */
        extractCodeword(ctx->rawSram, bitOff, rawCw);

        /* get helper data for this codeword */
        XMEMSET(helperCw, 0, WC_PUF_CW_BYTES);
        for (j = 0; j < WC_PUF_HELPER_LEN; j++) {
            setBit(helperCw, WC_PUF_HELPER_OFF + j,
                   getBit(helperData, i * WC_PUF_HELPER_LEN + j));
        }

        /* noisy codeword = raw XOR helper */
        for (j = 0; j < WC_PUF_CW_BYTES; j++) {
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
        #ifdef WOLFSSL_CHECK_MEM_ZERO
            wc_MemZero_Check(rawCw, sizeof(rawCw));
            wc_MemZero_Check(helperCw, sizeof(helperCw));
            wc_MemZero_Check(noisyCw, sizeof(noisyCw));
            wc_MemZero_Check(msg, sizeof(msg));
        #endif
            ctx->flags &= (word32)~WC_PUF_FLAG_READY;
            return PUF_RECONSTRUCT_E;
        }

        /* store k stable bits per codeword, bit-packed */
        for (j = 0; j < WC_PUF_BCH_K; j++) {
            setBit(ctx->stableBits, i * WC_PUF_BCH_K + j, getBit(msg, j));
        }
    }

    /* compute identity */
    ret = wc_PufHashDirect(ctx->stableBits, WC_PUF_STABLE_BYTES, ctx->identity);

    /* zeroize sensitive stack buffers */
    ForceZero(rawCw, sizeof(rawCw));
    ForceZero(helperCw, sizeof(helperCw));
    ForceZero(noisyCw, sizeof(noisyCw));
    ForceZero(msg, sizeof(msg));
#ifdef WOLFSSL_CHECK_MEM_ZERO
    wc_MemZero_Check(rawCw, sizeof(rawCw));
    wc_MemZero_Check(helperCw, sizeof(helperCw));
    wc_MemZero_Check(noisyCw, sizeof(noisyCw));
    wc_MemZero_Check(msg, sizeof(msg));
#endif

    if (ret != 0)
        return PUF_RECONSTRUCT_E;

    ctx->flags |= WC_PUF_FLAG_READY;
    return 0;
}

int wc_PufReconstruct(wc_PufCtx* ctx, const byte* helperData, word32 helperSz)
{
    /* the profile id passed is the library's own, so the check inside the Ex
     * variant is trivially satisfied and behaviour matches prior releases */
    return wc_PufReconstructEx(ctx, helperData, helperSz,
                               (word32)WC_PUF_PROFILE_ID);
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

/* Report the compile-time PUF profile parameters. Each output pointer is
 * optional (may be NULL). Enrollment and reconstruction firmware must agree
 * on all of these; persist them (or WC_PUF_PROFILE_ID) with the helper data
 * and compare before reconstruction to detect a build mismatch. */
int wc_PufGetParams(int* m, int* n, int* k, int* t, int* numCodewords)
{
    WOLFSSL_ENTER("wc_PufGetParams");

    /* every output is optional, but an all-NULL call is a programming error;
     * reject it to match the argument-validation convention of the module */
    if (m == NULL && n == NULL && k == NULL && t == NULL &&
            numCodewords == NULL)
        return BAD_FUNC_ARG;

    if (m != NULL)
        *m = WC_PUF_BCH_M;
    if (n != NULL)
        *n = WC_PUF_BCH_N;
    if (k != NULL)
        *k = WC_PUF_BCH_K;
    if (t != NULL)
        *t = WC_PUF_BCH_T;
    if (numCodewords != NULL)
        *numCodewords = WC_PUF_NUM_CODEWORDS;

    return 0;
}

/* Report the profile fingerprint the LIBRARY was compiled with. The
 * WC_PUF_PROFILE_ID macro necessarily reflects the calling application's own
 * build, so comparing the two detects a library/application mismatch that no
 * length check can see. */
word32 wc_PufGetProfileId(void)
{
    WOLFSSL_ENTER("wc_PufGetProfileId");

    return (word32)WC_PUF_PROFILE_ID;
}

/* Copy out the enrollment helper data. Applications should use this rather
 * than reading wc_PufCtx.helperData directly: the size varies with the
 * selected profile. */
int wc_PufGetHelperData(wc_PufCtx* ctx, byte* helper, word32 helperSz)
{
    WOLFSSL_ENTER("wc_PufGetHelperData");

    if (ctx == NULL || helper == NULL)
        return BAD_FUNC_ARG;
    if (!(ctx->flags & WC_PUF_FLAG_ENROLLED))
        return PUF_ENROLL_E;
    if (helperSz < WC_PUF_HELPER_BYTES)
        return PUF_ENROLL_E;

    XMEMCPY(helper, ctx->helperData, WC_PUF_HELPER_BYTES);
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

/* implementation-private macros - not part of the public WC_PUF_ namespace */
#undef BCH_GENPOLY_DEG
#undef BCH_REG_MSB_MASK

#endif /* WOLFSSL_PUF */
