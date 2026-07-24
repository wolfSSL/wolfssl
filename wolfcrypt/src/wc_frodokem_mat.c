/* wc_frodokem_mat.c
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

/* Low-level matrix arithmetic and encoding routines for the FrodoKEM reference
 * implementation.
 *
 * Implementation based on:
 *   https://www.ietf.org/archive/id/draft-longa-cfrg-frodokem-03.txt
 *
 * The matrix A is generated on the fly (a row at a time) using AES-128
 * (Section 6.7.1) or SHAKE128 (Section 6.7.2) of the draft, selected per
 * parameter set and build.  The full matrix is never stored, keeping memory
 * usage independent of q and small relative to n^2.
 */

#define _WC_BUILDING_WC_FRODOKEM_MAT_C

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#include <wolfssl/wolfcrypt/wc_frodokem_mat.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/memory.h>
#if defined(USE_INTEL_SPEEDUP) || defined(FRODOKEM_HAVE_SVE) || \
    (defined(FRODOKEM_HAVE_NEON_ASM) && defined(__aarch64__))
#include <wolfssl/wolfcrypt/cpuid.h>
#endif
#ifdef WOLFSSL_FRODOKEM_AES
    #include <wolfssl/wolfcrypt/aes.h>
    #if defined(NO_AES) || !defined(WOLFSSL_AES_DIRECT) || \
        !defined(HAVE_AES_ECB)
        #error "WOLFSSL_FRODOKEM_AES needs WOLFSSL_AES_DIRECT and HAVE_AES_ECB."
    #endif
#endif

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#ifdef WOLFSSL_HAVE_FRODOKEM

/* On AArch64 the presence of NEON (Advanced SIMD) is verified at run time via
 * IS_AARCH64_ASIMD, so the NEON asm and the portable-C matrix path are both
 * compiled and the choice is made per call (matching the sha256/chacha
 * pattern). AArch32 NEON and Thumb2 guarantee their SIMD at compile time
 * (-mfpu / DSP) and always use the asm. */
#if defined(FRODOKEM_HAVE_NEON_ASM) && defined(__aarch64__)
    #define FRODOKEM_HAVE_NEON_RUNTIME
#endif

/* Prefix for the S * A dispatch: use SME when the CPU has it (a small S-column
 * gather then the ZA-tile outer product), else fall through. Empty when SME is
 * not compiled in. */
#ifdef FRODOKEM_HAVE_SME
#define FRODOKEM_SA_ACCUM_SME(out, s, row, j, n)                               \
        if (frodokem_sme_svl_ok) {                                             \
            frodokem_sa_accum_sme_wrap((out), (s), (row), (j), (n));           \
        }                                                                      \
        else
#define FRODOKEM_AS_ACCUM_SME(out, s, row, i, n)                               \
        if (frodokem_sme_svl_ok) {                                             \
            frodokem_as_accum_sme_wrap((out), (s), (row), (i), (n));           \
        }                                                                      \
        else
#else
#define FRODOKEM_SA_ACCUM_SME(out, s, row, j, n) /* SME not compiled in */
#define FRODOKEM_AS_ACCUM_SME(out, s, row, i, n) /* SME not compiled in */
#endif

/* Dispatch the S * A and A * S accumulates. SME > SVE > NEON (if Advanced SIMD)
 * > portable C, chosen per call from the cached CPU flags. */
#if defined(FRODOKEM_HAVE_SVE)
#define FRODOKEM_SA_ACCUM(out, s, row, j, n)                                   \
    do {                                                                       \
        FRODOKEM_SA_ACCUM_SME(out, s, row, j, n)                               \
        if (IS_AARCH64_SVE(cpuid_flags)) {                                     \
            frodokem_sa_accum_sve((out), (s), (row), (j), (n));                \
        }                                                                      \
        else if (IS_AARCH64_ASIMD(cpuid_flags)) {                             \
            frodokem_sa_accum_arm((out), (s), (row), (j), (n));                \
        }                                                                      \
        else {                                                                 \
            frodokem_sa_accum((out), (s), (row), (j), (n));                    \
        }                                                                      \
    } while (0)
#define FRODOKEM_AS_ACCUM(out, s, row, i, n)                                   \
    do {                                                                       \
        FRODOKEM_AS_ACCUM_SME(out, s, row, i, n)                               \
        if (IS_AARCH64_SVE(cpuid_flags)) {                                     \
            frodokem_as_accum_sve((out), (s), (row), (i), (n));                \
        }                                                                      \
        else if (IS_AARCH64_ASIMD(cpuid_flags)) {                             \
            frodokem_as_accum_arm((out), (s), (row), (i), (n));                \
        }                                                                      \
        else {                                                                 \
            frodokem_as_accum((out), (s), (row), (i), (n));                    \
        }                                                                      \
    } while (0)
#elif defined(FRODOKEM_HAVE_NEON_RUNTIME)
#define FRODOKEM_SA_ACCUM(out, s, row, j, n)                                   \
    do {                                                                       \
        FRODOKEM_SA_ACCUM_SME(out, s, row, j, n)                               \
        if (IS_AARCH64_ASIMD(cpuid_flags)) {                                   \
            frodokem_sa_accum_arm((out), (s), (row), (j), (n));                \
        }                                                                      \
        else {                                                                 \
            frodokem_sa_accum((out), (s), (row), (j), (n));                    \
        }                                                                      \
    } while (0)
#define FRODOKEM_AS_ACCUM(out, s, row, i, n)                                   \
    do {                                                                       \
        FRODOKEM_AS_ACCUM_SME(out, s, row, i, n)                               \
        if (IS_AARCH64_ASIMD(cpuid_flags)) {                                   \
            frodokem_as_accum_arm((out), (s), (row), (i), (n));                \
        }                                                                      \
        else {                                                                 \
            frodokem_as_accum((out), (s), (row), (i), (n));                    \
        }                                                                      \
    } while (0)
#elif defined(FRODOKEM_HAVE_ARM_ASM)
#define FRODOKEM_SA_ACCUM(out, s, row, j, n)                                   \
    frodokem_sa_accum_arm((out), (s), (row), (j), (n))
#define FRODOKEM_AS_ACCUM(out, s, row, i, n)                                   \
    frodokem_as_accum_arm((out), (s), (row), (i), (n))
#endif

/* Accumulate a whole FRODOKEM_ROW_MULT-row A*S batch (as generated per AES gen
 * call). On AArch64 NEON without SVE/SME, FRODOKEM_ROW_MULT is 4 and a dedicated
 * 4-row routine fuses all four rows so each S column block is loaded once and
 * multiply-accumulated into all four output rows (halving S-load issue pressure).
 * Otherwise accumulate FRODOKEM_AS_ACCUM_ROWS rows at a time with the base
 * routine (which the macro dispatches to SME/SVE/NEON/portable at run time). */
#if defined(FRODOKEM_HAVE_NEON_ASM) && defined(__aarch64__) && \
    !defined(FRODOKEM_HAVE_SVE) && !defined(FRODOKEM_HAVE_SME)
#define FRODOKEM_AS_ACCUM_BATCH(out, s, row, i, n)                             \
    frodokem_as_accum_x4_neon((out), (s), (row), (i), (n))
#define FRODOKEM_SA_ACCUM_BATCH(out, s, row, j, n)                             \
    frodokem_sa_accum_x4_neon((out), (s), (row), (j), (n))
#elif defined(FRODOKEM_HAVE_ARM_ASM)
#define FRODOKEM_AS_ACCUM_BATCH(out, s, row, i, n)                             \
    do {                                                                       \
        int k_;                                                                \
        for (k_ = 0; k_ < FRODOKEM_ROW_MULT; k_ += FRODOKEM_AS_ACCUM_ROWS) {   \
            FRODOKEM_AS_ACCUM((out), (s), (row) + k_ * (n), (i) + k_, (n));     \
        }                                                                      \
    } while (0)
#define FRODOKEM_SA_ACCUM_BATCH(out, s, row, j, n)                             \
    do {                                                                       \
        int k_;                                                                \
        for (k_ = 0; k_ < FRODOKEM_ROW_MULT; k_ += FRODOKEM_AS_ACCUM_ROWS) {   \
            FRODOKEM_SA_ACCUM((out), (s), (row) + k_ * (n), (j) + k_, (n));     \
        }                                                                      \
    } while (0)
#endif

/* FrodoKEM-976 and -1344 use D=16 packing and SHAKE-256 noise generation;
 * FrodoKEM-640 uses D=15 packing and SHAKE-128. Only compile the code paths
 * the enabled parameter sets can actually reach. */
#if defined(WOLFSSL_WC_FRODOKEM_976) || defined(WOLFSSL_WC_FRODOKEM_1344)
    #define FRODOKEM_D16_SHAKE256
#endif
#ifdef WOLFSSL_WC_FRODOKEM_640
    #define FRODOKEM_D15_SHAKE128
#endif

/* restrict qualifier for the matrix multiply inner loops. The A-row scratch
 * and the output-row slices never overlap, so flagging them lets the compiler
 * vectorize each contiguous accumulation stream (without it the aliasing
 * analysis gives up and the loops stay scalar). Falls back to nothing on
 * compilers without a restrict keyword - the code stays correct either way. */
#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L)
    #define FRODOKEM_RESTRICT restrict
#elif defined(__GNUC__) || defined(__clang__) || defined(_MSC_VER)
    #define FRODOKEM_RESTRICT __restrict
#else
    #define FRODOKEM_RESTRICT
#endif

#if defined(USE_INTEL_SPEEDUP) || defined(FRODOKEM_HAVE_SVE) || \
    defined(FRODOKEM_HAVE_NEON_RUNTIME)
/* Cached CPU feature flags used to select SIMD routines: AVX2 / BMI2 Keccak in
 * matrix-A generation on Intel, and the SVE / NEON matrix ops on AArch64 (NEON
 * is gated on Advanced SIMD). Populated once by frodokem_init(). */
static cpuid_flags_t cpuid_flags = WC_CPUID_INITIALIZER;
#endif

#ifdef FRODOKEM_HAVE_SME
/* The SME kernels compute the whole nbar x nbar (8 x 8) product in one ZA.S
 * tile, which needs a streaming vector length (SVL) of at least 256 bits (32
 * bytes). HWCAP2_SME alone does not guarantee that, so the SVL is measured and
 * the SME path is selected only when it is wide enough (else SVE / NEON runs).
 * Set by frodokem_init(); 0 until then, so SME stays off until measured. */
static int frodokem_sme_svl_ok = 0;

/* Streaming vector length in bytes (SVL / 8), read with RDSVL. Encoded as a raw
 * instruction so no SME assembler support is required. Only called when SME is
 * present (IS_AARCH64_SME), so RDSVL will not trap. */
static WC_INLINE int frodokem_sme_svl_bytes(void)
{
    word64 svl;
    __asm__ volatile(".inst 0x04bf5820\n\t"   /* rdsvl x0, #1 */
                     "mov %0, x0"
                     : "=r"(svl) : : "x0");
    return (int)svl;
}
#endif

/* Initialize FrodoKEM internal state. Caches the CPU feature flags used to
 * dispatch the SIMD implementations. Called from wc_FrodoKemKey_Init; safe to
 * call repeatedly (the flags are read from the CPU only once). */
void frodokem_init(void)
{
#if defined(USE_INTEL_SPEEDUP) || defined(FRODOKEM_HAVE_SVE) || \
    defined(FRODOKEM_HAVE_NEON_RUNTIME)
    cpuid_get_flags_ex(&cpuid_flags);
#endif
#ifdef FRODOKEM_HAVE_SME
    /* SME needs SVL >= 256 bits (>= 32 bytes) for the 8 x 8 ZA.S tile. */
    frodokem_sme_svl_ok = IS_AARCH64_SME(cpuid_flags) &&
        (frodokem_sme_svl_bytes() >= 32);
#endif
}

#ifdef FRODOKEM_HAVE_SME
/* Portable-C A * S accumulate (defined later): the SME fallback on allocation
 * failure. Compiled here since FRODOKEM_HAVE_SME implies AArch64 NEON
 * runtime. */
static void frodokem_as_accum(word16* out, const word16* s, const word16* row,
    int i, int n);

/* Reshape a rows x n matrix (row-major) into the SME UMOPA interleaved layout:
 * dst[t*rows*2 + 2*r + e] = m[r*n + 2*t + e].
 *
 * @param  [out]  dst   Interleaved output (rows * n word16).
 * @param  [in]   m     Source matrix (rows * n, row-major).
 * @param  [in]   rows  Number of rows in the source matrix.
 * @param  [in]   n     Number of columns (a multiple of 2).
 */
static void frodokem_sme_interleave(word16* dst, const word16* m, int rows,
    int n)
{
    int t;
    int r;
    for (t = 0; t < n / 2; t++) {
        for (r = 0; r < rows; r++) {
            dst[t * rows * 2 + 2 * r + 0] = m[r * n + 2 * t + 0];
            dst[t * rows * 2 + 2 * r + 1] = m[r * n + 2 * t + 1];
        }
    }
}

/* Gather the S column pair for column j (sc[2*i + e] = s[i*n + j + e]) into a
 * small stack buffer and run the SME S * A accumulate. The A-row interleave is
 * done inside the asm, so no large scratch is needed.
 *
 * @param  [in, out]  out  S * A accumulator (nbar * n, row-major).
 * @param  [in]       s    Matrix S (nbar * n, row-major).
 * @param  [in]       row  The two generated A rows (2 * n coefficients).
 * @param  [in]       j    First column of the S column pair.
 * @param  [in]       n    Matrix dimension n.
 */
static void frodokem_sa_accum_sme_wrap(word16* out, const word16* s,
    const word16* row, int j, int n)
{
    word16 sc[2 * FRODOKEM_NBAR];
    int i;

    for (i = 0; i < FRODOKEM_NBAR; i++) {
        sc[2 * i + 0] = s[i * n + j + 0];
        sc[2 * i + 1] = s[i * n + j + 1];
    }
    frodokem_sa_accum_sme(out, sc, row, n);
    /* sc held two columns of the secret matrix S^T. */
#ifdef WOLFSSL_CHECK_MEM_ZERO
    wc_MemZero_Add("frodokem sme sc", sc, sizeof(sc));
#endif
    ForceZero(sc, sizeof(sc));
#ifdef WOLFSSL_CHECK_MEM_ZERO
    wc_MemZero_Check(sc, sizeof(sc));
#endif
}

/* Transpose the two A rows and S into the SME interleaved layout, then run the
 * SME A * S accumulate. Both need reshaping (unlike S * A), so this uses
 * scratch and falls back to the portable-C accumulate if it cannot be had.
 *
 * @param  [in, out]  out  A * S accumulator (n * nbar, row-major).
 * @param  [in]       s    Matrix S^T (nbar * n, row-major).
 * @param  [in]       row  The two generated A rows (2 * n coefficients).
 * @param  [in]       i    Index of the first of the two generated A rows.
 * @param  [in]       n    Matrix dimension n.
 */
static void frodokem_as_accum_sme_wrap(word16* out, const word16* s,
    const word16* row, int i, int n)
{
    word16* at;
    word16* st;

    at = (word16*)XMALLOC((size_t)2 * (size_t)n * sizeof(word16), NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    st = (word16*)XMALLOC((size_t)FRODOKEM_NBAR * (size_t)n * sizeof(word16),
        NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if ((at != NULL) && (st != NULL)) {
        frodokem_sme_interleave(at, row, 2, n);
        frodokem_sme_interleave(st, s, FRODOKEM_NBAR, n);
        frodokem_as_accum_sme(out, at, st, i, n);
    }
    else {
        frodokem_as_accum(out, s, row, i, n);
    }
    /* st held the interleaved secret matrix S^T. */
    if (st != NULL) {
        ForceZero(st, (size_t)FRODOKEM_NBAR * (size_t)n * sizeof(word16));
    }
    XFREE(at, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(st, NULL, DYNAMIC_TYPE_TMP_BUFFER);
}
#endif /* FRODOKEM_HAVE_SME */

/******************************************************************************/
/* Packing and unpacking of matrices to/from byte strings (Section 6.2).      */
/******************************************************************************/

/* Pack a matrix of nElem coefficients into a byte string.
 *
 * Each coefficient contributes its low 'd' bits, most-significant bit first,
 * and the resulting bit string is packed into bytes most-significant bit first
 * (Section 6.2).
 *
 * @param  [out]  out    Output byte string. Must be (nElem * d + 7) / 8 bytes.
 * @param  [in]   in     Matrix coefficients in row-major order.
 * @param  [in]   nElem  Number of coefficients.
 * @param  [in]   d      Number of bits per coefficient.
 */
void frodokem_pack(byte* out, const word16* in, int nElem, int d)
{
#if !defined(FRODOKEM_D16_SHAKE256) || !defined(FRODOKEM_D15_SHAKE128)
    (void)d;
#endif

#if defined(FRODOKEM_D16_SHAKE256) && defined(FRODOKEM_D15_SHAKE128)
    if (d == 16)
#endif
#ifdef FRODOKEM_D16_SHAKE256
    {
        /* Coefficients are byte-aligned: each is stored as a big-endian 16-bit
         * value (most-significant byte first). */
#ifdef BIG_ENDIAN_ORDER
        /* word16 memory is already big-endian: a straight copy. */
        XMEMCPY(out, in, (size_t)nElem * sizeof(word16));
#else
        int i;

        for (i = 0; i < nElem; i++) {
            out[2 * i]     = (byte)(in[i] >> 8);
            out[2 * i + 1] = (byte)(in[i] & 0xff);
        }
#endif
    }
#endif
#if defined(FRODOKEM_D16_SHAKE256) && defined(FRODOKEM_D15_SHAKE128)
    else
#endif
#ifdef FRODOKEM_D15_SHAKE128
    {
        /* d == 15 (FrodoKEM-640): stream 15 significant bits per coefficient,
         * most-significant bit first, through a bit accumulator, emitting a
         * byte whenever 8 bits are buffered. nElem is a multiple of nbar (8),
         * so packing ends on a byte boundary and every output byte is fully
         * assigned - no pre-clear needed. This is endian-independent. */
        word32 acc = 0;
        int accBits = 0;
        int oi = 0;
        int i;

        for (i = 0; i < nElem; i++) {
            acc = (acc << 15) | (word32)(in[i] & 0x7fff);
            accBits += 15;
            do {
                accBits -= 8;
                out[oi++] = (byte)(acc >> accBits);
            } while (accBits >= 8);
            acc &= ((word32)1 << accBits) - 1;
        }
    }
#endif
}

/* Unpack a byte string into a matrix of nElem coefficients.
 *
 * The inverse of frodokem_pack().
 *
 * @param  [out]  out    Output matrix coefficients in row-major order.
 * @param  [in]   in     Input byte string.
 * @param  [in]   nElem  Number of coefficients.
 * @param  [in]   d      Number of bits per coefficient.
 */
void frodokem_unpack(word16* out, const byte* in, int nElem, int d)
{
#if !defined(FRODOKEM_D16_SHAKE256) || !defined(FRODOKEM_D15_SHAKE128)
    (void)d;
#endif

#if defined(FRODOKEM_D16_SHAKE256) && defined(FRODOKEM_D15_SHAKE128)
    if (d == 16)
#endif
#ifdef FRODOKEM_D16_SHAKE256
    {
        /* Byte-aligned coefficients: inverse of the big-endian byte swap. */
#ifdef BIG_ENDIAN_ORDER
        /* word16 memory is already big-endian: a straight copy. */
        XMEMCPY(out, in, (size_t)nElem * sizeof(word16));
#else
        int i;

        for (i = 0; i < nElem; i++) {
            out[i] = (word16)(((word16)in[2 * i] << 8) | in[2 * i + 1]);
        }
#endif
    }
#endif
#if defined(FRODOKEM_D16_SHAKE256) && defined(FRODOKEM_D15_SHAKE128)
    else
#endif
#ifdef FRODOKEM_D15_SHAKE128
    {
        /* d == 15 (FrodoKEM-640): read 15 bits per coefficient, most-
         * significant bit first, through a bit accumulator fed a byte at a
         * time. nElem is a multiple of nbar (8), so the stream is consumed
         * exactly. This is endian-independent. */
        word32 acc = 0;
        int accBits = 0;
        int ii = 0;
        int i;

        for (i = 0; i < nElem; i++) {
            while (accBits < 15) {
                acc = (acc << 8) | in[ii++];
                accBits += 8;
            }
            accBits -= 15;
            out[i] = (word16)((acc >> accBits) & 0x7fff);
            acc &= ((word32)1 << accBits) - 1;
        }
    }
#endif
}

/* Serialize a matrix of word16 coefficients as little-endian 16-bit values.
 *
 * Used for the secret matrix S^T in the private key, whose two's-complement
 * samples are stored as full 16-bit little-endian words (Section 6.3).
 *
 * @param  [out]  out  Output byte string (2 * cnt bytes).
 * @param  [in]   mat  Matrix coefficients.
 * @param  [in]   cnt  Number of coefficients.
 */
void frodokem_store_matrix(byte* out, const word16* mat, int cnt)
{
#ifdef BIG_ENDIAN_ORDER
    int i;

    /* Swap each coefficient from big-endian memory to little-endian bytes. */
    for (i = 0; i < cnt; i++) {
        out[2 * i]     = (byte)(mat[i] & 0xff);
        out[2 * i + 1] = (byte)((mat[i] >> 8) & 0xff);
    }
#else
    /* Coefficients are already little-endian in memory: a straight copy. */
    XMEMCPY(out, mat, (size_t)cnt * sizeof(word16));
#endif
}

/* Deserialize little-endian 16-bit values into a matrix of word16 coefficients.
 *
 * The inverse of frodokem_store_matrix(): loads the secret matrix S^T from the
 * private key.
 *
 * @param  [out]  mat  Output matrix coefficients.
 * @param  [in]   in   Input byte string (2 * cnt bytes).
 * @param  [in]   cnt  Number of coefficients.
 */
void frodokem_load_matrix(word16* mat, const byte* in, int cnt)
{
#ifdef BIG_ENDIAN_ORDER
    int i;

    /* Swap each coefficient from little-endian bytes to big-endian memory. */
    for (i = 0; i < cnt; i++) {
        mat[i] = (word16)(in[2 * i] | ((word16)in[2 * i + 1] << 8));
    }
#else
    /* Coefficients are already little-endian in memory: a straight copy. */
    XMEMCPY(mat, in, (size_t)cnt * sizeof(word16));
#endif
}

/******************************************************************************/
/* Encoding and decoding of messages to/from matrices (Section 6.1).          */
/******************************************************************************/

/* Encode a message bit string into an nbar x nbar matrix.
 *
 * Groups of B bits (least-significant bit of each byte first, Section 6.1) are
 * turned into a coefficient scaled by q / 2^B, i.e. shifted left by (D - B).
 *
 * @param  [out]  c     Output matrix (nbar * nbar coefficients).
 * @param  [in]   msg   Message of B * nbar * nbar bits (lenSec bytes).
 * @param  [in]   d     Number of bits per coefficient (D).
 * @param  [in]   bits  Number of message bits per coefficient (B).
 */
void frodokem_key_encode(word16* c, const byte* msg, int d, int bits)
{
    int idx;
    int k;
    word32 bitPos = 0;
    int nElem = FRODOKEM_NBAR_SQ;
    int shift = d - bits;

    for (idx = 0; idx < nElem; idx++) {
        unsigned int val = 0;

        for (k = 0; k < bits; k++) {
            /* Bits taken least-significant first within each byte. */
            int bit = (msg[bitPos >> 3] >> (bitPos & 7)) & 1;
            val |= ((unsigned int)bit) << k;
            bitPos++;
        }
        c[idx] = (word16)(val << shift);
    }
}

/* Decode an nbar x nbar matrix into a message bit string.
 *
 * The inverse of frodokem_key_encode(): each coefficient is rounded to
 * the nearest multiple of q / 2^B and the resulting B bits are emitted
 * least-significant bit first.
 *
 * @param  [out]  msg  Output message of B * nbar * nbar bits (lenSec bytes).
 * @param  [in]   c    Input matrix (nbar * nbar coefficients).
 * @param  [in]   p    FrodoKEM parameters.
 */
void frodokem_key_decode(byte* msg, const word16* c, const FrodoKemParams* p)
{
    int idx;
    int k;
    word32 bitPos = 0;
    int nElem = FRODOKEM_NBAR_SQ;
    int shift = p->d - p->b;
    /* Rounding constant: q / 2^(B+1) = 2^(D - B - 1). */
    unsigned int rnd = 1u << (shift - 1);
    unsigned int mask = (1u << p->b) - 1;

    XMEMSET(msg, 0, (size_t)p->lenSec);

    for (idx = 0; idx < nElem; idx++) {
        /* Reduce the coefficient modulo q before rounding. */
        unsigned int v = (unsigned int)(c[idx] & p->qMask);
        unsigned int dec = ((v + rnd) >> shift) & mask;

        for (k = 0; k < p->b; k++) {
            int bit = (dec >> k) & 1;
            msg[bitPos >> 3] |= (byte)(bit << (bitPos & 7));
            bitPos++;
        }
    }
}

/******************************************************************************/
/* SHAKE hashing.                                                             */
/******************************************************************************/

#ifdef FRODOKEM_D15_SHAKE128
/* Compute out = SHAKE128(in0 || in1, outLen). Used for the hashing function
 * of FrodoKEM-640 (D=15).
 *
 * @param  [in]   shake   Reusable SHAKE object (re-initialized here).
 * @param  [in]   in0     First input buffer.
 * @param  [in]   len0    Length in bytes of the first input.
 * @param  [in]   in1     Second input buffer.
 * @param  [in]   len1    Length in bytes of the second input.
 * @param  [out]  out     Output buffer.
 * @param  [in]   outLen  Number of bytes to output.
 * @return  0 on success, negative on hash error.
 */
static int frodokem_shake128(wc_Shake* shake, const byte* in0, word32 len0,
    const byte* in1, word32 len1, byte* out, word32 outLen)
{
    int ret;

    ret = wc_InitShake128(shake, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_Shake128_Update(shake, in0, len0);
    }
    if (ret == 0) {
        ret = wc_Shake128_Update(shake, in1, len1);
    }
    if (ret == 0) {
        ret = wc_Shake128_Final(shake, out, outLen);
    }

    return ret;
}
#endif /* FRODOKEM_D15_SHAKE128 */

#ifdef FRODOKEM_D16_SHAKE256
/* Compute out = SHAKE256(in0 || in1, outLen). Used for the hashing function
 * of FrodoKEM-976 / -1344 (D=16).
 *
 * @param  [in]   shake   Reusable SHAKE object (re-initialized here).
 * @param  [in]   in0     First input buffer.
 * @param  [in]   len0    Length in bytes of the first input.
 * @param  [in]   in1     Second input buffer.
 * @param  [in]   len1    Length in bytes of the second input.
 * @param  [out]  out     Output buffer.
 * @param  [in]   outLen  Number of bytes to output.
 * @return  0 on success, negative on hash error.
 */
static int frodokem_shake256(wc_Shake* shake, const byte* in0, word32 len0,
    const byte* in1, word32 len1, byte* out, word32 outLen)
{
    int ret;

    ret = wc_InitShake256(shake, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_Shake256_Update(shake, in0, len0);
    }
    if (ret == 0) {
        ret = wc_Shake256_Update(shake, in1, len1);
    }
    if (ret == 0) {
        ret = wc_Shake256_Final(shake, out, outLen);
    }

    return ret;
}
#endif /* FRODOKEM_D16_SHAKE256 */

/* Compute out = SHAKE(in0 || in1, outLen), selecting SHAKE128 for FrodoKEM-640
 * and SHAKE256 for FrodoKEM-976 / -1344.
 *
 * @param  [in]   p       FrodoKEM parameters.
 * @param  [in]   shake   Reusable SHAKE object (re-initialized here).
 * @param  [in]   in0     First input buffer.
 * @param  [in]   len0    Length in bytes of the first input.
 * @param  [in]   in1     Second input buffer.
 * @param  [in]   len1    Length in bytes of the second input.
 * @param  [out]  out     Output buffer.
 * @param  [in]   outLen  Number of bytes to output.
 * @return  0 on success, negative on hash error.
 */
int frodokem_shake(const FrodoKemParams* p, wc_Shake* shake, const byte* in0,
    word32 len0, const byte* in1, word32 len1, byte* out, word32 outLen)
{
    int ret = 0;

#if !defined(FRODOKEM_D16_SHAKE256) || !defined(FRODOKEM_D15_SHAKE128)
    (void)p;
#endif
#if defined(FRODOKEM_D16_SHAKE256) && defined(FRODOKEM_D15_SHAKE128)
    if (p->useShake256)
#endif
#ifdef FRODOKEM_D16_SHAKE256
    {
        ret = frodokem_shake256(shake, in0, len0, in1, len1, out, outLen);
    }
#endif
#if defined(FRODOKEM_D16_SHAKE256) && defined(FRODOKEM_D15_SHAKE128)
    else
#endif
#ifdef FRODOKEM_D15_SHAKE128
    {
        ret = frodokem_shake128(shake, in0, len0, in1, len1, out, outLen);
    }
#endif

    return ret;
}

/* One-shot SHAKE over a single contiguous input buffer, selecting SHAKE128 for
 * FrodoKEM-640 and SHAKE256 for FrodoKEM-976 / -1344.
 *
 * @param  [in]   p       FrodoKEM parameters.
 * @param  [in]   shake   Reusable SHAKE object (re-initialized here).
 * @param  [in]   in      Input buffer.
 * @param  [in]   inLen   Length of input in bytes.
 * @param  [out]  out     Output buffer.
 * @param  [in]   outLen  Number of bytes to output.
 * @return  0 on success, negative on hash error.
 */
int frodokem_shake_oneshot(const FrodoKemParams* p, wc_Shake* shake,
    const byte* in, word32 inLen, byte* out, word32 outLen)
{
    int ret = 0;

#if !defined(FRODOKEM_D16_SHAKE256) || !defined(FRODOKEM_D15_SHAKE128)
    (void)p;
#endif
#if defined(FRODOKEM_D16_SHAKE256) && defined(FRODOKEM_D15_SHAKE128)
    if (p->useShake256)
#endif
#ifdef FRODOKEM_D16_SHAKE256
    {
        ret = wc_InitShake256(shake, NULL, INVALID_DEVID);
        if (ret == 0) {
            ret = wc_Shake256_Update(shake, in, inLen);
        }
        if (ret == 0) {
            ret = wc_Shake256_Final(shake, out, outLen);
        }
    }
#endif
#if defined(FRODOKEM_D16_SHAKE256) && defined(FRODOKEM_D15_SHAKE128)
    else
#endif
#ifdef FRODOKEM_D15_SHAKE128
    {
        ret = wc_InitShake128(shake, NULL, INVALID_DEVID);
        if (ret == 0) {
            ret = wc_Shake128_Update(shake, in, inLen);
        }
        if (ret == 0) {
            ret = wc_Shake128_Final(shake, out, outLen);
        }
    }
#endif

    return ret;
}

/******************************************************************************/
/* Error sampling (Section 6.5).                                              */
/******************************************************************************/

/* The sign/magnitude split of the 16-bit random value: bit 0 is the sign, the
 * remaining 15 bits form the magnitude looked up against the CDF table. */
#define FRODOKEM_SAMPLE_PRND(val)  ((word16)((val) >> 1))
#define FRODOKEM_SAMPLE_SIGN(val)  ((word16)((val) & 1))

/* Apply the sign: e = (-1)^sign * e, held as a 16-bit two's complement value.
 * It is deliberately NOT reduced modulo q: the secret and error matrices are
 * stored (and serialized in the secret key) in this form, and all downstream
 * matrix arithmetic reduces modulo q at the end. */
#define FRODOKEM_SAMPLE_APPLY_SIGN(e, sign) \
    ((word16)(((e) ^ (word16)(0 - (sign))) + (sign)))

/* The scalar-C samplers are the fallback for CPUs without the SIMD sampler.
 * On AArch64 they are also compiled as the run-time fallback used when the CPU
 * lacks Advanced SIMD (NEON). */
#if !defined(FRODOKEM_HAVE_NEON_ASM) || defined(FRODOKEM_HAVE_NEON_RUNTIME)
#ifdef WOLFSSL_FRODOKEM_SMALL
/* Sample a single value from the error distribution using the parameter set's
 * CDF table (Section 6.5).
 *
 * @param  [in]  val  16-bit random value (little-endian bytes assembled by the
 *                    caller: bit 0 is the sign, bits 1..15 the magnitude).
 * @param  [in]  p    FrodoKEM parameters.
 * @return  Sampled value (16-bit two's complement, not reduced modulo q).
 */
static word16 frodokem_sample(word16 val, const FrodoKemParams* p)
{
    int i;
    word16 prnd = FRODOKEM_SAMPLE_PRND(val);
    word16 sign = FRODOKEM_SAMPLE_SIGN(val);
    word16 e = 0;

    /* Constant-time count of table entries strictly less than prnd. The final
     * table entry (2^15 - 1) can never be exceeded, so it contributes zero. */
    for (i = 0; i < p->cdfLen; i++) {
        e = (word16)(e + (word16)((word16)(p->cdf[i] - prnd) >> 15));
    }

    return FRODOKEM_SAMPLE_APPLY_SIGN(e, sign);
}
#else
/* One constant-time CDF comparison: add 1 to e when table entry V < prnd, i.e.
 * when the 16-bit difference V - prnd borrows and sets bit 15. */
#define FRODOKEM_CDF_STEP(V) \
    e = (word16)(e + (word16)((word16)((V) - prnd) >> 15))

/* Per-parameter samplers with the CDF loop fully unrolled and the CDF values
 * (Table 5) used as literals - no table load or loop overhead. Each performs
 * the same constant-time count as the generic sampler above. */
#ifdef WOLFSSL_WC_FRODOKEM_640
/* Sample a single FrodoKEM-640 error value from its 13-entry CDF (Table 5).
 *
 * @param  [in]  val  16-bit random value (bit 0 is the sign, bits 1..15 the
 *                    magnitude).
 * @return  Sampled value (16-bit two's complement, not reduced modulo q).
 */
static word16 frodokem_sample_640(word16 val)
{
    word16 prnd = FRODOKEM_SAMPLE_PRND(val);
    word16 sign = FRODOKEM_SAMPLE_SIGN(val);
    word16 e = 0;

    FRODOKEM_CDF_STEP(4643);
    FRODOKEM_CDF_STEP(13363);
    FRODOKEM_CDF_STEP(20579);
    FRODOKEM_CDF_STEP(25843);
    FRODOKEM_CDF_STEP(29227);
    FRODOKEM_CDF_STEP(31145);
    FRODOKEM_CDF_STEP(32103);
    FRODOKEM_CDF_STEP(32525);
    FRODOKEM_CDF_STEP(32689);
    FRODOKEM_CDF_STEP(32745);
    FRODOKEM_CDF_STEP(32762);
    FRODOKEM_CDF_STEP(32766);
    FRODOKEM_CDF_STEP(32767);

    return FRODOKEM_SAMPLE_APPLY_SIGN(e, sign);
}
#endif
#ifdef WOLFSSL_WC_FRODOKEM_976
/* Sample a single FrodoKEM-976 error value from its 11-entry CDF (Table 5).
 *
 * @param  [in]  val  16-bit random value (bit 0 is the sign, bits 1..15 the
 *                    magnitude).
 * @return  Sampled value (16-bit two's complement, not reduced modulo q).
 */
static word16 frodokem_sample_976(word16 val)
{
    word16 prnd = FRODOKEM_SAMPLE_PRND(val);
    word16 sign = FRODOKEM_SAMPLE_SIGN(val);
    word16 e = 0;

    FRODOKEM_CDF_STEP(5638);
    FRODOKEM_CDF_STEP(15915);
    FRODOKEM_CDF_STEP(23689);
    FRODOKEM_CDF_STEP(28571);
    FRODOKEM_CDF_STEP(31116);
    FRODOKEM_CDF_STEP(32217);
    FRODOKEM_CDF_STEP(32613);
    FRODOKEM_CDF_STEP(32731);
    FRODOKEM_CDF_STEP(32760);
    FRODOKEM_CDF_STEP(32766);
    FRODOKEM_CDF_STEP(32767);

    return FRODOKEM_SAMPLE_APPLY_SIGN(e, sign);
}
#endif
#ifdef WOLFSSL_WC_FRODOKEM_1344
/* Sample a single FrodoKEM-1344 error value from its 7-entry CDF (Table 5).
 *
 * @param  [in]  val  16-bit random value (bit 0 is the sign, bits 1..15 the
 *                    magnitude).
 * @return  Sampled value (16-bit two's complement, not reduced modulo q).
 */
static word16 frodokem_sample_1344(word16 val)
{
    word16 prnd = FRODOKEM_SAMPLE_PRND(val);
    word16 sign = FRODOKEM_SAMPLE_SIGN(val);
    word16 e = 0;

    FRODOKEM_CDF_STEP(9142);
    FRODOKEM_CDF_STEP(23462);
    FRODOKEM_CDF_STEP(30338);
    FRODOKEM_CDF_STEP(32361);
    FRODOKEM_CDF_STEP(32725);
    FRODOKEM_CDF_STEP(32765);
    FRODOKEM_CDF_STEP(32767);

    return FRODOKEM_SAMPLE_APPLY_SIGN(e, sign);
}
#endif
#undef FRODOKEM_CDF_STEP
#endif /* WOLFSSL_FRODOKEM_SMALL */
#endif /* !FRODOKEM_HAVE_NEON_ASM || FRODOKEM_HAVE_NEON_RUNTIME */

/* The i-th 16-bit little-endian noise value. Sampling is in place on little-
 * endian (r aliases mat), so the native word16 is read directly; on big-endian
 * the two little-endian bytes are assembled. */
#ifdef BIG_ENDIAN_ORDER
    #define FRODOKEM_NOISE_VAL(mat, r, i) \
        ((word16)((r)[2 * (i)] | ((word16)(r)[2 * (i) + 1] << 8)))
#else
    #define FRODOKEM_NOISE_VAL(mat, r, i)  ((mat)[i])
#endif

/* Sample cnt error coefficients from a buffer of random bytes.
 *
 * Sampling is elementwise, so the matrix shape is irrelevant - only the total
 * coefficient count is needed. The per-parameter sampler is chosen once, ahead
 * of the loop.
 *
 * @param  [in, out]  mat  Little-endian: raw noise bytes in place, replaced by
 *                         the sampled coefficients. Big-endian: coefficients
 *                         out (bytes come from r).
 * @param  [in]       cnt  Number of coefficients.
 * @param  [in]       r    Random bytes (2 * cnt); used on big-endian only.
 * @param  [in]       p    FrodoKEM parameters.
 */
static void frodokem_sample_matrix(word16* mat, int cnt, const byte* r,
    const FrodoKemParams* p)
{
    int i;

#ifndef BIG_ENDIAN_ORDER
    /* Little-endian reads the value straight from mat (sampled in place). */
    (void)r;
#endif

#if defined(FRODOKEM_HAVE_NEON_ASM) && !defined(FRODOKEM_HAVE_NEON_RUNTIME)
    (void)i;
    frodokem_sample_neon(mat, cnt, p->cdf, p->cdfLen);
#else
#ifdef FRODOKEM_HAVE_NEON_RUNTIME
    if (IS_AARCH64_ASIMD(cpuid_flags)) {
        frodokem_sample_neon(mat, cnt, p->cdf, p->cdfLen);
    }
    else
#endif
#ifdef FRODOKEM_HAVE_MATRIX_ASM_AVX512
    if (IS_INTEL_AVX512(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        frodokem_sample_avx512(mat, cnt, p->cdf, p->cdfLen);
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
#ifdef FRODOKEM_HAVE_MATRIX_ASM
    if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        frodokem_sample_avx2(mat, cnt, p->cdf, p->cdfLen);
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
    {
#ifdef WOLFSSL_FRODOKEM_SMALL
    for (i = 0; i < cnt; i++) {
        mat[i] = frodokem_sample(FRODOKEM_NOISE_VAL(mat, r, i), p);
    }
#else
    switch (p->n) {
#ifdef WOLFSSL_WC_FRODOKEM_640
    case WC_FRODOKEM_640_N:
        for (i = 0; i < cnt; i++) {
            mat[i] = frodokem_sample_640(FRODOKEM_NOISE_VAL(mat, r, i));
        }
        break;
#endif
#ifdef WOLFSSL_WC_FRODOKEM_976
    case WC_FRODOKEM_976_N:
        for (i = 0; i < cnt; i++) {
            mat[i] = frodokem_sample_976(FRODOKEM_NOISE_VAL(mat, r, i));
        }
        break;
#endif
#ifdef WOLFSSL_WC_FRODOKEM_1344
    case WC_FRODOKEM_1344_N:
        for (i = 0; i < cnt; i++) {
            mat[i] = frodokem_sample_1344(FRODOKEM_NOISE_VAL(mat, r, i));
        }
        break;
#endif
    default:
        break;
    }
#endif /* WOLFSSL_FRODOKEM_SMALL */
    }
#endif /* FRODOKEM_HAVE_NEON_ASM */
}

/* SHAKE-128 rate (block size) in bytes. */
#define FRODOKEM_SHAKE128_RATE  168
/* SHAKE-256 rate (block size) in bytes. */
#define FRODOKEM_SHAKE256_RATE  136

/* Generate and sample the noise matrices for one FrodoKEM operation.
 *
 * Absorbs the caller-assembled 'domain || seedSE' (seInput, 1 + lenSE bytes)
 * into a SHAKE XOF and squeezes the noise stream. Whole SHAKE blocks are
 * squeezed straight into the destination buffers; tmp holds only the final
 * partial block of a region, whose unused tail continues the stream into the
 * next region. This is byte-identical to a single large SHAKE squeeze but
 * avoids copying full blocks. A region of cnt word16 occupies exactly 2 * cnt
 * bytes - the same as its noise - so each region is sampled in place, needing
 * no separate noise buffer. The second region is optional (cnt1 == 0 to skip
 * it): MakeKey's two matrices live in separate buffers, whereas Encapsulate and
 * Decapsulate pass everything as one region. Region 1, when present, is much
 * larger than one SHAKE block. The SHAKE variant is chosen once; each branch
 * uses only its own primitives - SHAKE-256 for FrodoKEM-976/-1344, SHAKE-128
 * for -640.
 *
 * The caller owns seInput and tmp: seInput is a small buffer whose first byte
 * holds the domain and whose next lenSE bytes hold the seed (so no seed copy or
 * seed zeroize happens here); tmp is scratch of at least a SHAKE block, for
 * which callers pass the matrix-A row scratch (unused during noise generation).
 *
 * @param  [in]   p        FrodoKEM parameters.
 * @param  [in]   shake    Reusable SHAKE object (re-initialized here).
 * @param  [in]   seInput  Domain byte followed by the seed (1 + lenSE bytes).
 * @param  [out]  tmp      Scratch for one squeezed block (>= SHAKE rate bytes).
 * @param  [out]  mat0     First region output buffer (cnt0 coefficients).
 * @param  [in]   cnt0     Number of coefficients in the first region.
 * @param  [out]  mat1     Second region output buffer, or NULL when cnt1 == 0.
 * @param  [in]   cnt1     Number of coefficients in the second region, or 0.
 *                         Precondition: a non-zero cnt1 must span more than one
 *                         SHAKE block (2 * cnt1 >= the SHAKE rate) so the
 *                         region-1 partial-block length (2 * cnt1 - lead) does
 *                         not underflow; MakeKey, the only cnt1 > 0 caller,
 *                         passes cnt1 = n * nbar and always satisfies this.
 * @return  0 on success, negative on error.
 */
int frodokem_gen_noise(const FrodoKemParams* p, wc_Shake* shake,
    const byte* seInput, byte* tmp, word16* mat0, int cnt0, word16* mat1,
    int cnt1)
{
    /* Initialized: with a single parameter set built, only one SHAKE branch is
     * compiled and the compiler cannot see that p->useShake256 always selects
     * it, so ret needs a defined value on the (unreachable) fall-through. */
    int ret = 0;
    word32 inLen;
    byte* mat0_8 = (byte*)mat0;
    byte* mat1_8 = (byte*)mat1;

    inLen = (word32)(1 + p->lenSE);

#ifdef FRODOKEM_D16_SHAKE256
    if (p->useShake256 &&
        ((ret = wc_InitShake256(shake, NULL, INVALID_DEVID)) == 0)) {
        word32 len0 = (word32)(2 * cnt0);
        word32 full = len0 / FRODOKEM_SHAKE256_RATE;

        ret = wc_Shake256_Absorb(shake, seInput, inLen);
        /* Whole blocks straight into mat0, final partial block via tmp. */
        if (ret == 0) {
            ret = wc_Shake256_SqueezeBlocks(shake, mat0_8, full);
        }
        if (ret == 0) {
            ret = wc_Shake256_SqueezeBlocks(shake, tmp, 1);
        }
        if (ret == 0) {
            len0 -= full * FRODOKEM_SHAKE256_RATE;
            XMEMCPY(mat0_8 + full * FRODOKEM_SHAKE256_RATE, tmp, len0);
            frodokem_sample_matrix(mat0, cnt0, mat0_8, p);
        }
        if ((ret == 0) && (cnt1 > 0)) {
            /* tmp[len0 ..] is the start of region 1 (stream continues). The
             * only cnt1 > 0 caller (MakeKey) passes a region 1 of many blocks,
             * so 2 * cnt1 > lead and the unsigned rest cannot underflow. */
            word32 lead = FRODOKEM_SHAKE256_RATE - len0;
            word32 rest = (word32)(2 * cnt1) - lead;

            XMEMCPY(mat1_8, tmp + len0, lead);
            full = rest / FRODOKEM_SHAKE256_RATE;
            ret = wc_Shake256_SqueezeBlocks(shake, mat1_8 + lead, full);
            if (ret == 0) {
                ret = wc_Shake256_SqueezeBlocks(shake, tmp, 1);
                if (ret == 0) {
                    rest -= full * FRODOKEM_SHAKE256_RATE;
                    XMEMCPY(mat1_8 + lead + full * FRODOKEM_SHAKE256_RATE, tmp,
                        rest);
                }
            }
            if (ret == 0) {
                frodokem_sample_matrix(mat1, cnt1, mat1_8, p);
            }
        }
    }
#endif
#ifdef FRODOKEM_D15_SHAKE128
    if ((!p->useShake256) &&
        ((ret = wc_InitShake128(shake, NULL, INVALID_DEVID)) == 0)) {
        word32 len0 = (word32)(2 * cnt0);
        word32 full = len0 / FRODOKEM_SHAKE128_RATE;

        ret = wc_Shake128_Absorb(shake, seInput, inLen);
        /* Whole blocks straight into mat0, final partial block via tmp. */
        if (ret == 0) {
            ret = wc_Shake128_SqueezeBlocks(shake, mat0_8, full);
        }
        if (ret == 0) {
            ret = wc_Shake128_SqueezeBlocks(shake, tmp, 1);
        }
        if (ret == 0) {
            len0 -= full * FRODOKEM_SHAKE128_RATE;
            XMEMCPY(mat0_8 + full * FRODOKEM_SHAKE128_RATE, tmp, len0);
            frodokem_sample_matrix(mat0, cnt0, mat0_8, p);
        }
        if ((ret == 0) && (cnt1 > 0)) {
            /* tmp[len0 ..] is the start of region 1 (stream continues). The
             * only cnt1 > 0 caller (MakeKey) passes a region 1 of many blocks,
             * so 2 * cnt1 > lead and the unsigned rest cannot underflow. */
            word32 lead = FRODOKEM_SHAKE128_RATE - len0;
            word32 rest = (word32)(2 * cnt1) - lead;

            XMEMCPY(mat1_8, tmp + len0, lead);
            full = rest / FRODOKEM_SHAKE128_RATE;
            ret = wc_Shake128_SqueezeBlocks(shake, mat1_8 + lead, full);
            if (ret == 0) {
                ret = wc_Shake128_SqueezeBlocks(shake, tmp, 1);
                if (ret == 0) {
                    rest -= full * FRODOKEM_SHAKE128_RATE;
                    XMEMCPY(mat1_8 + lead + full * FRODOKEM_SHAKE128_RATE, tmp,
                        rest);
                }
            }
            if (ret == 0) {
                frodokem_sample_matrix(mat1, cnt1, mat1_8, p);
            }
        }
    }
#endif

    return ret;
}

/******************************************************************************/
/* Generation of matrix A and matrix multiplications (Sections 6.7, 6.4).     */
/******************************************************************************/

/* Reduce a freshly generated A row (n coefficients) in place, once the AES/
 * SHAKE output has been written into row as bytes. On big-endian each little-
 * endian 16-bit value is reassembled (no reduction). Then, only when q != 2^16,
 * the values are reduced mod q with qmask - for q == 2^16 (FrodoKEM-976/-1344)
 * the 16-bit values are already valid coefficients so no mask is applied. The
 * nbar (== 8) step is unrolled; n is a multiple of nbar.
 *
 * @param  [in, out]  row    A row bytes in; reduced coefficients out (n).
 * @param  [in]       n      Number of coefficients in the row.
 * @param  [in]       qmask  Reduction mask (q - 1); 0xFFFF when q == 2^16.
 */
static void frodokem_a_row_reduce(word16* row, int n, int qmask)
{
#ifdef BIG_ENDIAN_ORDER
    /* Reassemble each little-endian 16-bit value in place (no reduction). */
    {
        const byte* rowBytes = (const byte*)row;
        int k;

        for (k = 0; k < n; k += FRODOKEM_NBAR) {
            row[k + 0] = (word16)(rowBytes[2 * (k + 0)] |
                ((word16)rowBytes[2 * (k + 0) + 1] << 8));
            row[k + 1] = (word16)(rowBytes[2 * (k + 1)] |
                ((word16)rowBytes[2 * (k + 1) + 1] << 8));
            row[k + 2] = (word16)(rowBytes[2 * (k + 2)] |
                ((word16)rowBytes[2 * (k + 2) + 1] << 8));
            row[k + 3] = (word16)(rowBytes[2 * (k + 3)] |
                ((word16)rowBytes[2 * (k + 3) + 1] << 8));
            row[k + 4] = (word16)(rowBytes[2 * (k + 4)] |
                ((word16)rowBytes[2 * (k + 4) + 1] << 8));
            row[k + 5] = (word16)(rowBytes[2 * (k + 5)] |
                ((word16)rowBytes[2 * (k + 5) + 1] << 8));
            row[k + 6] = (word16)(rowBytes[2 * (k + 6)] |
                ((word16)rowBytes[2 * (k + 6) + 1] << 8));
            row[k + 7] = (word16)(rowBytes[2 * (k + 7)] |
                ((word16)rowBytes[2 * (k + 7) + 1] << 8));
        }
    }
#endif

    /* Reduce mod q only when necessary: q == 2^16 (976/1344) values are already
     * valid coefficients; only q == 2^15 (640) needs the reduction. */
#ifdef FRODOKEM_D15_SHAKE128
#ifdef FRODOKEM_D16_SHAKE256
    if (qmask != 0xffff)
#endif
    {
        int k;

        for (k = 0; k < n; k += FRODOKEM_NBAR) {
            row[k + 0] = (word16)(row[k + 0] & qmask);
            row[k + 1] = (word16)(row[k + 1] & qmask);
            row[k + 2] = (word16)(row[k + 2] & qmask);
            row[k + 3] = (word16)(row[k + 3] & qmask);
            row[k + 4] = (word16)(row[k + 4] & qmask);
            row[k + 5] = (word16)(row[k + 5] & qmask);
            row[k + 6] = (word16)(row[k + 6] & qmask);
            row[k + 7] = (word16)(row[k + 7] & qmask);
        }
    }
#endif

#ifndef FRODOKEM_D15_SHAKE128
    /* q == 2^16 only: no reduction (qmask unused). */
    (void)qmask;
#ifndef BIG_ENDIAN_ORDER
    /* Little-endian too: nothing at all to do. */
    (void)row;
    (void)n;
#endif
#endif
}

#ifdef WOLFSSL_FRODOKEM_AES
#ifndef FRODOKEM_HAVE_ARM_AES_ASM
/* Per-row C generator. On ARM with the crypto extension the whole batch is done
 * by frodokem_gen_a_rows_aes_arm, so this fallback is compiled out there. */
/* Generate cnt consecutive rows of matrix A (indices i .. i+cnt-1) using
 * AES-128 (Section 6.7.1). Each row is built, ECB-encrypted and reduced before
 * the next - keeping it hot in L1 - which measured faster than one ECB call
 * over the whole group (that spills the working set to L2). Consuming cnt rows
 * per accumulate call is still a win over one dispatch call per row.
 *
 * @param  [out]  rows  Output rows (cnt * n coefficients, contiguous).
 * @param  [in]   aes   AES object keyed with seedA.
 * @param  [in]   i     Index of the first row.
 * @param  [in]   cnt   Number of consecutive rows to generate.
 * @param  [in]   p     FrodoKEM parameters.
 * @return  0 on success.
 * @return  Negative on error from AES.
 */
static int frodokem_gen_a_rows_aes(word16* rows, Aes* aes, int i, int cnt,
    const FrodoKemParams* p)
{
    int ret;
    int r;
    int j;
    int n = p->n;
    byte* rowBytes = (byte*)rows;

    ret = 0;
    /* Process one row at a time (build its input blocks, ECB the whole row,
     * reduce) so each row stays hot in L1 through all three passes - measured
     * faster than one big ECB over the whole group, whose larger working set
     * spills to L2. For row i + r, block j is i+r || j || 0..0 (16-bit LE) and
     * an AES block yields FRODOKEM_NBAR (== 8) coefficients, so it lands at
     * rows[r*n] + 2*j = rowBytes + r*(2*n) + 2*j. In-place ECB is safe: each
     * block's output depends only on its own input. */
    for (r = 0; (ret == 0) && (r < cnt); r++) {
        byte* rowR = rowBytes + r * (2 * n);
        int idx = i + r;

        for (j = 0; j < n; j += FRODOKEM_NBAR) {
            byte* blk = rowR + 2 * j;

            blk[0] = (byte)(idx & 0xff);
            blk[1] = (byte)((idx >> 8) & 0xff);
            blk[2] = (byte)(j & 0xff);
            blk[3] = (byte)((j >> 8) & 0xff);
            XMEMSET(blk + 4, 0, 12);
        }

        ret = wc_AesEcbEncrypt(aes, rowR, rowR, (word32)(2 * n));
        if (ret == 0) {
            frodokem_a_row_reduce(rows + r * n, n, (int)p->qMask);
        }
    }

    return ret;
}
#endif /* !FRODOKEM_HAVE_ARM_AES_ASM */
#endif /* WOLFSSL_FRODOKEM_AES */

#ifdef WOLFSSL_FRODOKEM_SHAKE
/* The single-row scalar SHAKE generator is the fallback used when the 2-way
 * NEON permute is unavailable: on non-NEON targets, and on AArch64 at run time
 * when the CPU lacks Advanced SIMD. */
#if !defined(FRODOKEM_HAVE_SHAKE_NEON) || defined(FRODOKEM_HAVE_NEON_RUNTIME)
/* Generate a single row of matrix A using SHAKE128 (Section 6.7.2).
 *
 * The SHAKE output is squeezed into the row buffer itself and converted to
 * coefficients in place (ascending index), avoiding a separate scratch buffer.
 * The caller initializes shake as SHAKE-128 once before its row loop; each
 * wc_Shake128_Final here resets the state ready for the next row.
 *
 * @param  [in]   shake Reusable SHAKE object (SHAKE-128, ready to absorb).
 * @param  [out]  row   Output row of n coefficients (2 * n bytes).
 * @param  [in]   seedA Seed for A (FRODOKEM_SEEDA_SZ bytes).
 * @param  [in]   i     Row index.
 * @param  [in]   p     FrodoKEM parameters.
 * @return  0 on success.
 * @return  Negative on error from the hash function.
 */
static int frodokem_gen_a_row_shake(wc_Shake* shake, word16* row,
    const byte* seedA, int i, const FrodoKemParams* p)
{
    int ret;
#ifdef WOLFSSL_X86_64_BUILD
    byte* rowBytes = (byte*)row;
    word64* state = shake->s;
    word8 *state8 = (word8*)state;
    word16 l;
    static word16 inc = WC_SHA3_128_BLOCK_SIZE;

    /* The fast path writes the padded SHAKE-128 block straight into the Keccak
     * state and indexes it by lane, so the wc_Sha3 layout it relies on - a
     * 200-byte (25-lane) state and a rate of WC_SHA3_128_COUNT lanes - must
     * hold. Fail the build if wc_Sha3 ever changes rather than silently
     * generating wrong matrix-A output. */
    wc_static_assert(sizeof(shake->s) == 200);
    wc_static_assert(WC_SHA3_128_COUNT * 8 == WC_SHA3_128_BLOCK_SIZE);

    state8[0] = (byte)(i & 0xff);
    state8[1] = (byte)((i >> 8) & 0xff);
    XMEMCPY(state8 + 2, seedA, FRODOKEM_SEEDA_SZ);
    state8[2 + FRODOKEM_SEEDA_SZ] = 0x1f;
    XMEMSET(state8 + 2 + FRODOKEM_SEEDA_SZ + 1, 0,
        sizeof(shake->s) - (2 + FRODOKEM_SEEDA_SZ + 1));
    state8[WC_SHA3_128_COUNT * 8 - 1] = 0x80;

    for (l = 0; l + inc < 2 * p->n; l += inc) {
        BlockSha3(state);
        XMEMCPY(rowBytes + l, state8, WC_SHA3_128_BLOCK_SIZE);
    }
    BlockSha3(state);
    XMEMCPY(rowBytes + l, state8, (word32)(2 * p->n - l));

    ret = 0;
#else
    byte in[2 + FRODOKEM_SEEDA_SZ];
    byte* rowBytes = (byte*)row;

    /* Row index as 16-bit little-endian, followed by seedA. */
    in[0] = (byte)(i & 0xff);
    in[1] = (byte)((i >> 8) & 0xff);
    XMEMCPY(in + 2, seedA, FRODOKEM_SEEDA_SZ);

    ret = wc_Shake128_Update(shake, in, (word32)sizeof(in));
    if (ret == 0) {
        ret = wc_Shake128_Final(shake, rowBytes, (word32)(2 * p->n));
    }
#endif

    if (ret == 0) {
        /* Endian fix-up and mod-q reduction, done once over the whole row. */
        frodokem_a_row_reduce(row, p->n, (int)p->qMask);
    }

    return ret;
}
#endif /* !FRODOKEM_HAVE_SHAKE_NEON || FRODOKEM_HAVE_NEON_RUNTIME */

#ifdef FRODOKEM_HAVE_SHAKE_X4
/* Generate four rows of matrix A at once (indices i, i+1, i+2, i+3) with the
 * 4-way AVX2 SHAKE-128 permutation (Section 6.7.2). Byte-identical to four
 * frodokem_gen_a_row_shake calls, just computed in parallel lanes. Only built
 * on little-endian x86 with AVX2 (the layout below assumes little-endian).
 *
 * @param  [out]  rows   Four contiguous output rows (4 * n coefficients).
 * @param  [in]   seedA  Seed for A (FRODOKEM_SEEDA_SZ bytes).
 * @param  [in]   i      Index of the first of the four rows (i % 4 == 0).
 * @param  [in]   p      FrodoKEM parameters.
 * @return  0 on success.
 */
static int frodokem_gen_a_row_shake_x4(word16* rows, const byte* seedA,
    int i, const FrodoKemParams* p)
{
    /* Four interleaved SHAKE-128 states (Keccak-1600 is 25 word64 each): state
     * word m of lane k is at state[m * 4 + k]. */
    word64 state[25 * 4];
    int n = p->n;
    int lane;
    /* seedA-derived state words - the same in all four lanes. The bytes each
     * lane absorbs are: i (16-bit LE) || seedA (16) || 0x1f domain byte. */
    word64 w0 = ((word64)seedA[0] << 16) | ((word64)seedA[1] << 24) |
                ((word64)seedA[2] << 32) | ((word64)seedA[3] << 40) |
                ((word64)seedA[4] << 48) | ((word64)seedA[5] << 56);
    word64 w1 = (word64)seedA[6] | ((word64)seedA[7] << 8) |
                ((word64)seedA[8] << 16) | ((word64)seedA[9] << 24) |
                ((word64)seedA[10] << 32) | ((word64)seedA[11] << 40) |
                ((word64)seedA[12] << 48) | ((word64)seedA[13] << 56);
    word64 w2 = (word64)seedA[14] | ((word64)seedA[15] << 8) |
                ((word64)0x1f << 16);

    XMEMSET(state, 0, sizeof(state));
    for (lane = 0; lane < 4; lane++) {
        state[0 * 4 + lane] = w0 | (word64)((word32)(i + lane) & 0xffffU);
        state[1 * 4 + lane] = w1;
        state[2 * 4 + lane] = w2;
        /* pad10*1: top bit of last rate byte (byte 167 = word 20, byte 7). */
        state[(WC_SHA3_128_COUNT - 1) * 4 + lane] = (word64)0x80 << 56;
    }

    /* Squeeze 2*n bytes per lane, de-interleaved into the four rows. The rows
     * are contiguous, so lane k's output lands at (byte*)rows + k * (2 * n) =
     * rows + k * n, matching the row layout. 2*n is a multiple of 8. */
    sha3_blocksx4_out_avx2(state, (byte*)rows, (word32)(2 * n));

    /* 640 (q == 2^15) needs the mod-q mask; 976/1344 (q == 2^16) are already
     * valid coefficients. The four rows are contiguous, so mask all 4*n at
     * once with a single AVX2 pass (faster than four scalar per-lane passes;
     * we are already inside the AVX2 vector-register region). */
    if (p->qMask != 0xffff) {
        frodokem_a_rows_reduce_avx2(rows, (word32)(4 * n), (int)p->qMask);
    }

    return 0;
}
#endif /* FRODOKEM_HAVE_SHAKE_X4 */

#ifdef FRODOKEM_HAVE_SHAKE_X8
/* Generate eight rows of matrix A at once (indices i .. i+7) with the 8-way
 * AVX512 SHAKE-128 permutation (Section 6.7.2). Byte-identical to eight
 * frodokem_gen_a_row_shake calls, just computed in parallel lanes. Only built
 * on little-endian x86 with AVX512 (the layout below assumes little-endian).
 *
 * @param  [out]  rows   Eight contiguous output rows (8 * n coefficients).
 * @param  [in]   seedA  Seed for A (FRODOKEM_SEEDA_SZ bytes).
 * @param  [in]   i      Index of the first of the eight rows (i % 8 == 0).
 * @param  [in]   p      FrodoKEM parameters.
 * @return  0 on success.
 */
static int frodokem_gen_a_row_shake_x8(word16* rows, const byte* seedA,
    int i, const FrodoKemParams* p)
{
    /* Eight interleaved SHAKE-128 states (Keccak-1600 is 25 word64 each): state
     * word m of lane k is at state[m * 8 + k]. */
    word64 state[25 * 8];
    int n = p->n;
    int lane;
    /* seedA-derived state words - the same in all eight lanes. The bytes each
     * lane absorbs are: i (16-bit LE) || seedA (16) || 0x1f domain byte. */
    word64 w0 = ((word64)seedA[0] << 16) | ((word64)seedA[1] << 24) |
                ((word64)seedA[2] << 32) | ((word64)seedA[3] << 40) |
                ((word64)seedA[4] << 48) | ((word64)seedA[5] << 56);
    word64 w1 = (word64)seedA[6] | ((word64)seedA[7] << 8) |
                ((word64)seedA[8] << 16) | ((word64)seedA[9] << 24) |
                ((word64)seedA[10] << 32) | ((word64)seedA[11] << 40) |
                ((word64)seedA[12] << 48) | ((word64)seedA[13] << 56);
    word64 w2 = (word64)seedA[14] | ((word64)seedA[15] << 8) |
                ((word64)0x1f << 16);

    XMEMSET(state, 0, sizeof(state));
    for (lane = 0; lane < 8; lane++) {
        state[0 * 8 + lane] = w0 | (word64)((word32)(i + lane) & 0xffffU);
        state[1 * 8 + lane] = w1;
        state[2 * 8 + lane] = w2;
        /* pad10*1: top bit of last rate byte (byte 167 = word 20, byte 7). */
        state[(WC_SHA3_128_COUNT - 1) * 8 + lane] = (word64)0x80 << 56;
    }

    /* Squeeze 2*n bytes per lane, de-interleaved into the eight rows. Lane k's
     * output lands at (byte*)rows + k * (2 * n) = rows + k * n. 2*n is a
     * multiple of 8. */
    sha3_blocksx8_out_avx512(state, (byte*)rows, (word32)(2 * n));

    /* 640 (q == 2^15) needs the mod-q mask; 976/1344 (q == 2^16) are already
     * valid coefficients. The eight rows are contiguous, so mask all 8*n at
     * once (the AVX2 ymm pass runs fine inside this AVX512 region). */
    if (p->qMask != 0xffff) {
        frodokem_a_rows_reduce_avx2(rows, (word32)(8 * n), (int)p->qMask);
    }

    return 0;
}
#endif /* FRODOKEM_HAVE_SHAKE_X8 */

#ifdef FRODOKEM_HAVE_SHAKE_NEON
/* Generate two rows of matrix A at once (indices i, i+1) with the 2-way NEON
 * SHAKE-128 permutation (Section 6.7.2). Byte-identical to two
 * frodokem_gen_a_row_shake calls. The two Keccak states are laid out
 * contiguously - state[0..24] for row i, state[25..49] for row i+1 - so each
 * squeezed rate block copies straight to its row (no lane de-interleave).
 *
 * @param  [out]  rows   Two contiguous output rows (2 * n coefficients).
 * @param  [in]   seedA  Seed for A (FRODOKEM_SEEDA_SZ bytes).
 * @param  [in]   i      Index of the first of the two rows (i % 2 == 0).
 * @param  [in]   p      FrodoKEM parameters.
 * @return  0 on success.
 */
static int frodokem_gen_a_row_shake_x2(word16* rows, const byte* seedA,
    int i, const FrodoKemParams* p)
{
    /* Two 25-word Keccak states, contiguous: A then B. */
    word64 state[50];
    int n = p->n;
    int total = 2 * n;              /* output bytes per row */
    int off;
    byte* sA = (byte*)(state + 0);
    byte* sB = (byte*)(state + 25);
    byte* rowA = (byte*)(rows + 0);
    byte* rowB = (byte*)(rows + n);

    XMEMSET(state, 0, sizeof(state));
    /* Absorb i || seedA || 0x1f pad, with pad10*1 top bit at the last rate
     * byte (167). State A is index i, state B is index i+1. */
    sA[0] = (byte)(i & 0xff);
    sA[1] = (byte)((i >> 8) & 0xff);
    XMEMCPY(sA + 2, seedA, FRODOKEM_SEEDA_SZ);
    sA[2 + FRODOKEM_SEEDA_SZ] = 0x1f;
    sA[WC_SHA3_128_COUNT * 8 - 1] = 0x80;
    sB[0] = (byte)((i + 1) & 0xff);
    sB[1] = (byte)(((i + 1) >> 8) & 0xff);
    XMEMCPY(sB + 2, seedA, FRODOKEM_SEEDA_SZ);
    sB[2 + FRODOKEM_SEEDA_SZ] = 0x1f;
    sB[WC_SHA3_128_COUNT * 8 - 1] = 0x80;

    /* Squeeze 2*n bytes per row, a rate block per permutation. */
    for (off = 0; off < total; off += WC_SHA3_128_BLOCK_SIZE) {
        int blk = total - off;

        if (blk > WC_SHA3_128_BLOCK_SIZE) {
            blk = WC_SHA3_128_BLOCK_SIZE;
        }
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        /* Use the SHA3 crypto extension (EOR3/RAX1/XAR/BCAX) when present. */
        if (IS_AARCH64_SHA3(cpuid_flags)) {
            frodokem_sha3_x2_crypto(state);
        }
        else
#endif
        {
            frodokem_sha3_x2_neon(state);
        }
        XMEMCPY(rowA + off, sA, (size_t)blk);
        XMEMCPY(rowB + off, sB, (size_t)blk);
    }

    frodokem_a_row_reduce(rows + 0, n, (int)p->qMask);
    frodokem_a_row_reduce(rows + n, n, (int)p->qMask);

    return 0;
}
#endif /* FRODOKEM_HAVE_SHAKE_NEON */
#endif /* WOLFSSL_FRODOKEM_SHAKE */

/* The A-generating multiplies below have separate implementations per matrix-A
 * method (AES-128 or SHAKE128) so the method is chosen once, not per row. */

/* The scalar-C accumulates are the fallback for CPUs without the wide SIMD or
 * packed accumulate. AArch32 NEON and Thumb2 always use their asm, so these are
 * not compiled there; on AArch64 they are compiled as the run-time fallback for
 * CPUs without Advanced SIMD (NEON). */
#if !defined(FRODOKEM_HAVE_ARM_ASM) || defined(FRODOKEM_HAVE_NEON_RUNTIME)
/* Accumulate the contribution of one generated A row (index j) into S * A:
 * out[i*n + k] += s[i*n + j] * row[k] for i in [0, nbar), k in [0, n).
 *
 * Each output row is a separate contiguous accumulation stream. Flagging row
 * and the output slice as non-aliasing (they never overlap) lets the compiler
 * vectorize each stream; a form that updates all nbar rows in one fused loop
 * has too many possibly-aliasing pointers and stays scalar. Shared by the AES
 * and SHAKE paths (the arithmetic is identical; only A generation differs).
 *
 * @param  [in, out]  out  S * A accumulator (nbar * n, row-major).
 * @param  [in]       s    Matrix S (nbar * n, row-major).
 * @param  [in]       row  Generated A row j (n coefficients).
 * @param  [in]       j    Index of the generated A row.
 * @param  [in]       n    Matrix dimension n.
 */
static void frodokem_sa_accum(word16* out, const word16* s,
    const word16* FRODOKEM_RESTRICT row, int j, int n)
{
    int k;
#ifdef WOLFSSL_FRODOKEM_SMALL
    int i;

    for (i = 0; i < FRODOKEM_NBAR; i++) {
        word16 sij = s[i * n + j];
        word16* FRODOKEM_RESTRICT o = out + i * n;

        for (k = 0; k < n; k++) {
            o[k] = (word16)(o[k] + sij * row[k]);
        }
    }
#else
#if FRODOKEM_NBAR != 8
    #error "Unrolled frodokem_sa_accum assumes FRODOKEM_NBAR == 8."
#endif
    /* Unroll the nbar (== 8) output rows into 8 independent contiguous streams.
     * Each stays a single-stream accumulation the compiler vectorizes; the
     * unroll drops the outer-loop overhead. A single advancing output pointer,
     * with each S coefficient read just before its loop, keeps only one stream
     * live at a time (low register pressure). The output slice, wherever o
     * points, never overlaps row. */
    word16* FRODOKEM_RESTRICT o = out;
    word16 sij;

    sij = s[0 * n + j];
    for (k = 0; k < n; k++) {
        o[k] = (word16)(o[k] + sij * row[k]);
    }
    o += n;
    sij = s[1 * n + j];
    for (k = 0; k < n; k++) {
        o[k] = (word16)(o[k] + sij * row[k]);
    }
    o += n;
    sij = s[2 * n + j];
    for (k = 0; k < n; k++) {
        o[k] = (word16)(o[k] + sij * row[k]);
    }
    o += n;
    sij = s[3 * n + j];
    for (k = 0; k < n; k++) {
        o[k] = (word16)(o[k] + sij * row[k]);
    }
    o += n;
    sij = s[4 * n + j];
    for (k = 0; k < n; k++) {
        o[k] = (word16)(o[k] + sij * row[k]);
    }
    o += n;
    sij = s[5 * n + j];
    for (k = 0; k < n; k++) {
        o[k] = (word16)(o[k] + sij * row[k]);
    }
    o += n;
    sij = s[6 * n + j];
    for (k = 0; k < n; k++) {
        o[k] = (word16)(o[k] + sij * row[k]);
    }
    o += n;
    sij = s[7 * n + j];
    for (k = 0; k < n; k++) {
        o[k] = (word16)(o[k] + sij * row[k]);
    }
#endif
}

/* Accumulate the contribution of one generated A row (index i) into A * S:
 * out[i*nbar + k] += sum_j row[j] * s[k*n + j] for k in [0, nbar). row is the
 * generated A row i; column k of S is row k of S^T. out holds E on entry, so
 * the accumulation is in place. Shared by the AES and SHAKE paths (the
 * arithmetic is identical; only A generation differs).
 *
 * @param  [in, out]  out  A * S accumulator (n * nbar, row-major).
 * @param  [in]       s    Matrix S^T (nbar * n, row-major).
 * @param  [in]       row  Generated A row i (n coefficients).
 * @param  [in]       i    Index of the generated A row.
 * @param  [in]       n    Matrix dimension n.
 */
static void frodokem_as_accum(word16* out, const word16* s,
    const word16* row, int i, int n)
{
    int j;
#ifdef WOLFSSL_FRODOKEM_SMALL
    int k;

    for (k = 0; k < FRODOKEM_NBAR; k++) {
        /* column k of S == row k of S^T. out holds E on entry; word16 wraps
         * mod 2^16, reduced to mod q by the final mask. */
        const word16* sCol = s + k * n;
        word16 acc = out[i * FRODOKEM_NBAR + k];

        for (j = 0; j < n; j++) {
            acc = (word16)(acc + row[j] * sCol[j]);
        }
        out[i * FRODOKEM_NBAR + k] = acc;
    }
#else
#if FRODOKEM_NBAR != 8
    #error "Unrolled frodokem_as_accum assumes FRODOKEM_NBAR == 8."
#endif
    /* Unroll the nbar (== 8) output columns: keep 8 accumulators so each A
     * element row[j] is loaded once and reused across all 8 columns (8x less
     * row traffic than a separate dot product per column). Column k of S is
     * row k of S^T (s + k*n); out holds E on entry. */
    const word16* s0 = s;
    const word16* s1 = s + n;
    const word16* s2 = s + 2 * n;
    const word16* s3 = s + 3 * n;
    const word16* s4 = s + 4 * n;
    const word16* s5 = s + 5 * n;
    const word16* s6 = s + 6 * n;
    const word16* s7 = s + 7 * n;
    word16* outRow = out + i * FRODOKEM_NBAR;
    word16 a0 = outRow[0];
    word16 a1 = outRow[1];
    word16 a2 = outRow[2];
    word16 a3 = outRow[3];
    word16 a4 = outRow[4];
    word16 a5 = outRow[5];
    word16 a6 = outRow[6];
    word16 a7 = outRow[7];

    for (j = 0; j < n; j++) {
        word16 rj = row[j];

        a0 = (word16)(a0 + rj * s0[j]);
        a1 = (word16)(a1 + rj * s1[j]);
        a2 = (word16)(a2 + rj * s2[j]);
        a3 = (word16)(a3 + rj * s3[j]);
        a4 = (word16)(a4 + rj * s4[j]);
        a5 = (word16)(a5 + rj * s5[j]);
        a6 = (word16)(a6 + rj * s6[j]);
        a7 = (word16)(a7 + rj * s7[j]);
    }

    outRow[0] = a0;
    outRow[1] = a1;
    outRow[2] = a2;
    outRow[3] = a3;
    outRow[4] = a4;
    outRow[5] = a5;
    outRow[6] = a6;
    outRow[7] = a7;
#endif
}
#endif /* !FRODOKEM_HAVE_ARM_ASM || FRODOKEM_HAVE_NEON_RUNTIME */

#ifdef WOLFSSL_FRODOKEM_AES
/* Compute out += A * S (out holds E on entry) with A generated by AES-128.
 * See frodokem_mul_add_as_plus_e for the interface.
 *
 * @param  [in, out]  out    E on entry; out + A*S on exit (n * nbar).
 * @param  [in]       s      Secret matrix S^T (nbar * n, row-major).
 * @param  [in]       seedA  Seed for matrix-A generation (FRODOKEM_SEEDA_SZ).
 * @param  [in]       p      FrodoKEM parameters.
 * @param  [out]      row    Scratch for the generated A rows (ROW_MULT * n).
 * @param  [in]       aes    AES object for matrix-A generation.
 * @return  0 on success, negative on error.
 */
static int frodokem_mul_add_as_plus_e_aes(word16* out, const word16* s,
    const byte* seedA, const FrodoKemParams* p, word16* row, Aes* aes)
{
    int ret;
    int i;
    int n = p->n;

    /* Key the reusable AES object with seedA (the object is wc_AesInit'd once
     * in wc_FrodoKemKey_Init, so no per-call init/free here). */
    ret = wc_AesSetKeyDirect(aes, seedA, FRODOKEM_SEEDA_SZ, NULL,
        AES_ENCRYPTION);

    /* Generate the A rows in batches matching the fused asm accumulate (eight
     * with AVX512, four with AVX2); n is a multiple of 8 for every set. */
#ifdef FRODOKEM_HAVE_MATRIX_ASM_AVX512
    if ((ret == 0) && IS_INTEL_AVX512(cpuid_flags) &&
            (SAVE_VECTOR_REGISTERS2() == 0)) {
        for (i = 0; i < n; i += 8) {
            /* Widest matrix-A generator available at run time (cf. aes.c):
             * VAES (whole batch in one asm call), else the AES-NI register
             * kernel, else the per-row C generator. */
#ifdef FRODOKEM_HAVE_MATRIX_ASM_VAES
            if (IS_INTEL_VAES(cpuid_flags)) {
                frodokem_gen_a_rows_aes_avx512((byte*)row, row,
                    (const byte*)aes->key, i, 8, n, (int)p->qMask);
            }
            else
#endif
            if (IS_INTEL_AESNI(cpuid_flags)) {
                frodokem_gen_a_rows_aes_aesni((byte*)row, row,
                    (const byte*)aes->key, i, 8, n, (int)p->qMask);
            }
            else {
                ret = frodokem_gen_a_rows_aes(row, aes, i, 8, p);
                if (ret != 0) {
                    break;
                }
            }
            frodokem_as_accum_avx512(out, s, row, i, n);
        }
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
#ifdef FRODOKEM_HAVE_MATRIX_ASM
    if ((ret == 0) && IS_INTEL_AVX2(cpuid_flags) &&
            (SAVE_VECTOR_REGISTERS2() == 0)) {
        for (i = 0; i < n; i += 4) {
            /* Widest matrix-A generator available at run time (cf. aes.c):
             * VAES (whole batch in one asm call), else the AES-NI register
             * kernel, else the per-row C generator. */
#ifdef FRODOKEM_HAVE_MATRIX_ASM_VAES
            if (IS_INTEL_VAES(cpuid_flags)) {
                frodokem_gen_a_rows_aes_avx2((byte*)row, row,
                    (const byte*)aes->key, i, 4, n, (int)p->qMask);
            }
            else
#endif
            if (IS_INTEL_AESNI(cpuid_flags)) {
                frodokem_gen_a_rows_aes_aesni((byte*)row, row,
                    (const byte*)aes->key, i, 4, n, (int)p->qMask);
            }
            else {
                ret = frodokem_gen_a_rows_aes(row, aes, i, 4, p);
                if (ret != 0) {
                    break;
                }
            }
            frodokem_as_accum_avx2(out, s, row, i, n);
        }
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
#ifdef FRODOKEM_HAVE_ARM_ASM
    if (ret == 0) {
        for (i = 0; i < n; i += FRODOKEM_ROW_MULT) {
        #ifdef FRODOKEM_HAVE_ARM_AES_ASM
            /* The whole build + AES-ECB + reduce is one crypto-extension asm
             * call (in place). */
            frodokem_gen_a_rows_aes_arm((byte*)row, row,
                (const byte*)aes->key, i, FRODOKEM_ROW_MULT, n, (int)p->qMask);
        #else
            ret = frodokem_gen_a_rows_aes(row, aes, i, FRODOKEM_ROW_MULT, p);
            if (ret != 0) {
                break;
            }
        #endif
            /* Accumulate the whole FRODOKEM_ROW_MULT-row batch just generated. */
            FRODOKEM_AS_ACCUM_BATCH(out, s, row, i, n);
        }
    }
#else
    {
        for (i = 0; (ret == 0) && (i < n); i++) {
            ret = frodokem_gen_a_rows_aes(row, aes, i, 1, p);
            if (ret == 0) {
                frodokem_as_accum(out, s, row, i, n);
            }
        }
    }
#endif /* FRODOKEM_HAVE_ARM_ASM */

#ifdef FRODOKEM_D15_SHAKE128
    /* q == 2^15 (640) needs a final reduction mod q; for q == 2^16 (976/1344)
     * the word16 accumulation already reduced. */
#ifdef FRODOKEM_D16_SHAKE256
    if ((ret == 0) && (p->qMask != 0xffff))
#else
    if (ret == 0)
#endif
    {
        for (i = 0; i < FRODOKEM_NBAR * n; i++) {
            out[i] = (word16)(out[i] & p->qMask);
        }
    }
#endif /* FRODOKEM_D15_SHAKE128 */

    return ret;
}
#endif /* WOLFSSL_FRODOKEM_AES */

#ifdef WOLFSSL_FRODOKEM_SHAKE
/* Compute out += A * S (out holds E on entry) with A generated by SHAKE128.
 * See frodokem_mul_add_as_plus_e for the interface.
 *
 * @param  [in, out]  out    E on entry; out + A*S on exit (n * nbar).
 * @param  [in]       s      Secret matrix S^T (nbar * n, row-major).
 * @param  [in]       seedA  Seed for matrix-A generation (FRODOKEM_SEEDA_SZ).
 * @param  [in]       p      FrodoKEM parameters.
 * @param  [out]      row    Scratch for the generated A rows (ROW_MULT * n).
 * @param  [in]       shake  SHAKE object for matrix-A generation.
 * @return  0 on success, negative on error.
 */
static int frodokem_mul_add_as_plus_e_shake(word16* out, const word16* s,
    const byte* seedA, const FrodoKemParams* p, word16* row, wc_Shake* shake)
{
    int ret;
    int i;
    int n = p->n;

#ifdef FRODOKEM_HAVE_SHAKE_X8
    /* When AVX512 is available, generate and consume eight A rows at a time
     * with the 8-way SHAKE permutation. n is a multiple of 8 for every param
     * set, so there is no remainder loop. */
    if (IS_INTEL_AVX512(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        ret = 0;
        for (i = 0; i < n; i += 8) {
            ret = frodokem_gen_a_row_shake_x8(row, seedA, i, p);
            if (ret != 0) {
                break;
            }
            /* Fused 8-row A * S accumulate for all nbar output columns. */
            frodokem_as_accum_avx512(out, s, row, i, n);
        }
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif /* FRODOKEM_HAVE_SHAKE_X8 */
#ifdef FRODOKEM_HAVE_SHAKE_X4
    /* When AVX2 is available, generate and consume four A rows at a time with
     * the 4-way SHAKE permutation. n is a multiple of 4 for every parameter
     * set, so there is no remainder loop. */
    if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        ret = 0;
        for (i = 0; i < n; i += 4) {
            ret = frodokem_gen_a_row_shake_x4(row, seedA, i, p);
            if (ret != 0) {
                break;
            }
            /* Fused 4-row A * S accumulate for all nbar output columns. */
            frodokem_as_accum_avx2(out, s, row, i, n);
        }
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif /* FRODOKEM_HAVE_SHAKE_X4 */
#ifdef FRODOKEM_HAVE_SHAKE_NEON
    /* AArch64: with Advanced SIMD, generate and consume two A rows at a time
     * with the 2-way NEON SHAKE; without it, fall back to the scalar SHAKE and
     * portable-C accumulate (the 2-way permute is itself NEON). n is a multiple
     * of 2 for every set. */
    if (IS_AARCH64_ASIMD(cpuid_flags)) {
        (void)shake;
        ret = 0;
        for (i = 0; i < n; i += 2) {
            ret = frodokem_gen_a_row_shake_x2(row, seedA, i, p);
            if (ret != 0) {
                break;
            }
            FRODOKEM_AS_ACCUM(out, s, row, i, n);
        }
    }
    else {
        ret = wc_InitShake128(shake, NULL, INVALID_DEVID);
        for (i = 0; (ret == 0) && (i < n); i++) {
            ret = frodokem_gen_a_row_shake(shake, row, seedA, i, p);
            if (ret == 0) {
                frodokem_as_accum(out, s, row, i, n);
            }
        }
    }
#elif defined(FRODOKEM_HAVE_ARM_ASM)
    /* AArch32 (NEON or Thumb2): no parallel Keccak, so generate one A row at a
     * time with SHAKE-128 and consume it with the AArch32 A * S accumulate. */
    {
        ret = wc_InitShake128(shake, NULL, INVALID_DEVID);

        for (i = 0; (ret == 0) && (i < n); i++) {
            ret = frodokem_gen_a_row_shake(shake, row, seedA, i, p);
            if (ret == 0) {
                FRODOKEM_AS_ACCUM(out, s, row, i, n);
            }
        }
    }
#else
    {
        /* Matrix A is generated with SHAKE-128 for every parameter set.
         * Initialize the shared object once here; each row's Final resets it
         * for the next. */
        ret = wc_InitShake128(shake, NULL, INVALID_DEVID);

        for (i = 0; (ret == 0) && (i < n); i++) {
            ret = frodokem_gen_a_row_shake(shake, row, seedA, i, p);
            if (ret == 0) {
                frodokem_as_accum(out, s, row, i, n);
            }
        }
    }
#endif /* FRODOKEM_HAVE_SHAKE_NEON */

#ifdef FRODOKEM_D15_SHAKE128
    /* q == 2^15 (640) needs a final reduction mod q; for q == 2^16 (976/1344)
     * the word16 accumulation already reduced. */
#ifdef FRODOKEM_D16_SHAKE256
    if ((ret == 0) && (p->qMask != 0xffff))
#else
    if (ret == 0)
#endif
    {
        for (i = 0; i < FRODOKEM_NBAR * n; i++) {
            out[i] = (word16)(out[i] & p->qMask);
        }
    }
#endif /* FRODOKEM_D15_SHAKE128 */

    return ret;
}
#endif /* WOLFSSL_FRODOKEM_SHAKE */

/* Compute out = out + A * S, accumulating A * S into out which holds the error
 * matrix E on entry (all n x nbar); A is n x n and S is n x nbar. Taking E in
 * place saves the caller a copy (it samples E straight into out).
 *
 * S is supplied transposed (S^T, nbar x n) so column k of S is row k of s.
 * seedA, the parameters and the SHAKE / AES objects for matrix-A generation are
 * taken from key; dispatch is by the key parameters' useAes.
 *
 * @param  [in]       key    FrodoKEM key (provides seedA, params, SHAKE / AES).
 * @param  [in, out]  out    E on entry; out + A*S on exit (n * nbar).
 * @param  [in]       s      Secret matrix S^T (nbar * n, row-major).
 * @param  [out]      row    Scratch for the generated A rows (ROW_MULT * n).
 * @return  0 on success, negative on error.
 */
int frodokem_mul_add_as_plus_e(FrodoKemKey* key, word16* out, const word16* s,
    word16* row)
{
    const FrodoKemParams* p = key->params;
    int ret;

#ifdef WOLFSSL_FRODOKEM_AES
    if (p->useAes) {
        ret = frodokem_mul_add_as_plus_e_aes(out, s, key->seedA, p, row,
            &key->aes);
    }
    else
#endif
    {
#ifdef WOLFSSL_FRODOKEM_SHAKE
        ret = frodokem_mul_add_as_plus_e_shake(out, s, key->seedA, p, row,
            &key->shake);
#else
        ret = NOT_COMPILED_IN;
#endif
    }

    return ret;
}

#ifdef WOLFSSL_FRODOKEM_AES
/* Compute out = S * A + E (out holds E on entry) with A generated by AES-128.
 * See frodokem_mul_add_sa_plus_e for the interface.
 *
 * @param  [in, out]  out    E on entry; out + S*A on exit (nbar * n).
 * @param  [in]       s      Matrix S (nbar * n, row-major).
 * @param  [in]       seedA  Seed for matrix-A generation (FRODOKEM_SEEDA_SZ).
 * @param  [in]       p      FrodoKEM parameters.
 * @param  [out]      row    Scratch for the generated A rows (ROW_MULT * n).
 * @param  [in]       aes    AES object for matrix-A generation.
 * @return  0 on success, negative on error.
 */
static int frodokem_mul_add_sa_plus_e_aes(word16* out, const word16* s,
    const byte* seedA, const FrodoKemParams* p, word16* row, Aes* aes)
{
    int ret;
#ifdef FRODOKEM_D15_SHAKE128
    int i;
#endif
    int j;
    int n = p->n;

    /* Key the reusable AES object with seedA (the object is wc_AesInit'd once
     * in wc_FrodoKemKey_Init, so no per-call init/free here). */
    ret = wc_AesSetKeyDirect(aes, seedA, FRODOKEM_SEEDA_SZ, NULL,
        AES_ENCRYPTION);

    /* Generate the A rows in batches matching the fused asm accumulate (eight
     * with AVX512, four with AVX2); n is a multiple of 8 for every set. */
#ifdef FRODOKEM_HAVE_MATRIX_ASM_AVX512
    if ((ret == 0) && IS_INTEL_AVX512(cpuid_flags) &&
            (SAVE_VECTOR_REGISTERS2() == 0)) {
        for (j = 0; j < n; j += 8) {
            /* Widest matrix-A generator available at run time (cf. aes.c):
             * VAES (whole batch in one asm call), else the AES-NI register
             * kernel, else the per-row C generator. */
#ifdef FRODOKEM_HAVE_MATRIX_ASM_VAES
            if (IS_INTEL_VAES(cpuid_flags)) {
                frodokem_gen_a_rows_aes_avx512((byte*)row, row,
                    (const byte*)aes->key, j, 8, n, (int)p->qMask);
            }
            else
#endif
            if (IS_INTEL_AESNI(cpuid_flags)) {
                frodokem_gen_a_rows_aes_aesni((byte*)row, row,
                    (const byte*)aes->key, j, 8, n, (int)p->qMask);
            }
            else {
                ret = frodokem_gen_a_rows_aes(row, aes, j, 8, p);
                if (ret != 0) {
                    break;
                }
            }
            frodokem_sa_accum_avx512(out, s, row, j, n);
        }
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
#ifdef FRODOKEM_HAVE_MATRIX_ASM
    if ((ret == 0) && IS_INTEL_AVX2(cpuid_flags) &&
            (SAVE_VECTOR_REGISTERS2() == 0)) {
        for (j = 0; j < n; j += 4) {
            /* Widest matrix-A generator available at run time (cf. aes.c):
             * VAES (whole batch in one asm call), else the AES-NI register
             * kernel, else the per-row C generator. */
#ifdef FRODOKEM_HAVE_MATRIX_ASM_VAES
            if (IS_INTEL_VAES(cpuid_flags)) {
                frodokem_gen_a_rows_aes_avx2((byte*)row, row,
                    (const byte*)aes->key, j, 4, n, (int)p->qMask);
            }
            else
#endif
            if (IS_INTEL_AESNI(cpuid_flags)) {
                frodokem_gen_a_rows_aes_aesni((byte*)row, row,
                    (const byte*)aes->key, j, 4, n, (int)p->qMask);
            }
            else {
                ret = frodokem_gen_a_rows_aes(row, aes, j, 4, p);
                if (ret != 0) {
                    break;
                }
            }
            frodokem_sa_accum_avx2(out, s, row, j, n);
        }
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
#ifdef FRODOKEM_HAVE_ARM_ASM
    if (ret == 0) {
        for (j = 0; j < n; j += FRODOKEM_ROW_MULT) {
        #ifdef FRODOKEM_HAVE_ARM_AES_ASM
            /* The whole build + AES-ECB + reduce is one crypto-extension asm
             * call (in place). */
            frodokem_gen_a_rows_aes_arm((byte*)row, row,
                (const byte*)aes->key, j, FRODOKEM_ROW_MULT, n, (int)p->qMask);
        #else
            ret = frodokem_gen_a_rows_aes(row, aes, j, FRODOKEM_ROW_MULT, p);
            if (ret != 0) {
                break;
            }
        #endif
            /* Accumulate the whole FRODOKEM_ROW_MULT-row batch just generated. */
            FRODOKEM_SA_ACCUM_BATCH(out, s, row, j, n);
        }
    }
#else
    {
        /* Generate A a row at a time (index j) and accumulate its part. */
        for (j = 0; (ret == 0) && (j < n); j++) {
            ret = frodokem_gen_a_rows_aes(row, aes, j, 1, p);
            if (ret == 0) {
                frodokem_sa_accum(out, s, row, j, n);
            }
        }
    }
#endif /* FRODOKEM_HAVE_ARM_ASM */

#ifdef FRODOKEM_D15_SHAKE128
    /* q == 2^15 (640) needs a final reduction mod q; for q == 2^16 (976/1344)
     * the word16 accumulation already reduced. */
#ifdef FRODOKEM_D16_SHAKE256
    if ((ret == 0) && (p->qMask != 0xffff))
#else
    if (ret == 0)
#endif
    {
        for (i = 0; i < FRODOKEM_NBAR * n; i++) {
            out[i] = (word16)(out[i] & p->qMask);
        }
    }
#endif /* FRODOKEM_D15_SHAKE128 */

    return ret;
}
#endif /* WOLFSSL_FRODOKEM_AES */

#ifdef WOLFSSL_FRODOKEM_SHAKE
/* Compute out = S * A + E (out holds E on entry) with A generated by SHAKE128.
 * See frodokem_mul_add_sa_plus_e for the interface.
 *
 * @param  [in, out]  out    E on entry; out + S*A on exit (nbar * n).
 * @param  [in]       s      Matrix S (nbar * n, row-major).
 * @param  [in]       seedA  Seed for matrix-A generation (FRODOKEM_SEEDA_SZ).
 * @param  [in]       p      FrodoKEM parameters.
 * @param  [out]      row    Scratch for the generated A rows (ROW_MULT * n).
 * @param  [in]       shake  SHAKE object for matrix-A generation.
 * @return  0 on success, negative on error.
 */
static int frodokem_mul_add_sa_plus_e_shake(word16* out, const word16* s,
    const byte* seedA, const FrodoKemParams* p, word16* row, wc_Shake* shake)
{
    int ret;
#ifdef FRODOKEM_D15_SHAKE128
    int i;
#endif
    int j;
    int n = p->n;

#ifdef FRODOKEM_HAVE_SHAKE_X8
    /* When AVX512 is available, generate and consume eight A rows at a time
     * with the 8-way SHAKE permutation. n is a multiple of 8 for every param
     * set, so there is no remainder loop. */
    if (IS_INTEL_AVX512(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        ret = 0;
        for (j = 0; j < n; j += 8) {
            ret = frodokem_gen_a_row_shake_x8(row, seedA, j, p);
            if (ret != 0) {
                break;
            }
            /* Fused 8-row S * A accumulate for all nbar output rows. */
            frodokem_sa_accum_avx512(out, s, row, j, n);
        }
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif /* FRODOKEM_HAVE_SHAKE_X8 */
#ifdef FRODOKEM_HAVE_SHAKE_X4
    /* When AVX2 is available, generate and consume four A rows at a time with
     * the 4-way SHAKE permutation. n is a multiple of 4 for every parameter
     * set, so there is no remainder loop. */
    if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        ret = 0;
        for (j = 0; j < n; j += 4) {
            ret = frodokem_gen_a_row_shake_x4(row, seedA, j, p);
            if (ret != 0) {
                break;
            }
            /* Fused 4-row S * A accumulate for all nbar output rows. */
            frodokem_sa_accum_avx2(out, s, row, j, n);
        }
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif /* FRODOKEM_HAVE_SHAKE_X4 */
#ifdef FRODOKEM_HAVE_SHAKE_NEON
    /* AArch64: with Advanced SIMD, generate and consume two A rows at a time
     * with the 2-way NEON SHAKE (SVE or NEON accumulate); without it, fall back
     * to the scalar SHAKE and portable-C accumulate (the 2-way permute is
     * itself NEON). n is a multiple of 2 for every set. */
    if (IS_AARCH64_ASIMD(cpuid_flags)) {
        (void)shake;
        ret = 0;
        for (j = 0; j < n; j += 2) {
            ret = frodokem_gen_a_row_shake_x2(row, seedA, j, p);
            if (ret != 0) {
                break;
            }
            FRODOKEM_SA_ACCUM(out, s, row, j, n);
        }
    }
    else {
        ret = wc_InitShake128(shake, NULL, INVALID_DEVID);
        for (j = 0; (ret == 0) && (j < n); j++) {
            ret = frodokem_gen_a_row_shake(shake, row, seedA, j, p);
            if (ret == 0) {
                frodokem_sa_accum(out, s, row, j, n);
            }
        }
    }
#elif defined(FRODOKEM_HAVE_ARM_ASM)
    /* AArch32 (NEON or Thumb2): no parallel Keccak, so generate one A row at a
     * time with SHAKE-128 and consume it with the AArch32 S * A accumulate. */
    {
        ret = wc_InitShake128(shake, NULL, INVALID_DEVID);

        for (j = 0; (ret == 0) && (j < n); j++) {
            ret = frodokem_gen_a_row_shake(shake, row, seedA, j, p);
            if (ret == 0) {
                FRODOKEM_SA_ACCUM(out, s, row, j, n);
            }
        }
    }
#else
    {
        /* Matrix A is generated with SHAKE-128 for every parameter set.
         * Initialize the shared object once here; each row's Final resets it
         * for the next. */
        ret = wc_InitShake128(shake, NULL, INVALID_DEVID);

        /* Generate A a row at a time (index j) and accumulate it. */
        for (j = 0; (ret == 0) && (j < n); j++) {
            ret = frodokem_gen_a_row_shake(shake, row, seedA, j, p);
            if (ret == 0) {
                frodokem_sa_accum(out, s, row, j, n);
            }
        }
    }
#endif /* FRODOKEM_HAVE_SHAKE_NEON */

#ifdef FRODOKEM_D15_SHAKE128
    /* q == 2^15 (640) needs a final reduction mod q; for q == 2^16 (976/1344)
     * the word16 accumulation already reduced. */
#ifdef FRODOKEM_D16_SHAKE256
    if ((ret == 0) && (p->qMask != 0xffff))
#else
    if (ret == 0)
#endif
    {
        for (i = 0; i < FRODOKEM_NBAR * n; i++) {
            out[i] = (word16)(out[i] & p->qMask);
        }
    }
#endif /* FRODOKEM_D15_SHAKE128 */

    return ret;
}
#endif /* WOLFSSL_FRODOKEM_SHAKE */

/* Compute out = out + S * A, accumulating S * A into out which holds the error
 * matrix E on entry (all nbar x n); S is nbar x n and A is n x n. Taking E in
 * place saves the caller a copy (it samples E' straight into out). seedA, the
 * parameters and the SHAKE / AES objects for matrix-A generation are taken from
 * key; dispatch is by the key parameters' useAes.
 *
 * @param  [in]       key    FrodoKEM key (provides seedA, params, SHAKE / AES).
 * @param  [in, out]  out    E on entry; out + S*A on exit (nbar * n).
 * @param  [in]       s      Matrix S (nbar * n, row-major).
 * @param  [out]      row    Scratch for the generated A rows (ROW_MULT * n).
 * @return  0 on success, negative on error.
 */
int frodokem_mul_add_sa_plus_e(FrodoKemKey* key, word16* out, const word16* s,
    word16* row)
{
    const FrodoKemParams* p = key->params;
    int ret;

#ifdef WOLFSSL_FRODOKEM_AES
    if (p->useAes) {
        ret = frodokem_mul_add_sa_plus_e_aes(out, s, key->seedA, p, row,
            &key->aes);
    }
    else
#endif
    {
#ifdef WOLFSSL_FRODOKEM_SHAKE
        ret = frodokem_mul_add_sa_plus_e_shake(out, s, key->seedA, p, row,
            &key->shake);
#else
        ret = NOT_COMPILED_IN;
#endif
    }

    return ret;
}

/* Compute out = out + S * B, accumulating S * B into out which holds the error
 * matrix E on entry (all nbar x nbar). S is nbar x n and B is n x nbar. Taking
 * E in place saves the caller a copy (it samples E'' straight into out).
 *
 * @param  [in, out]  out  E on entry; out + S*B on exit (nbar * nbar).
 * @param  [in]       b    Matrix B (n * nbar, row-major).
 * @param  [in]       s    Matrix S (nbar * n, row-major).
 * @param  [in]       n      Matrix dimension n.
 * @param  [in]       qmask  Reduction mask (q - 1).
 */
void frodokem_mul_add_sb_plus_e(word16* out, const word16* b, const word16* s,
    int n, int qmask)
{
#if defined(FRODOKEM_HAVE_ARM_ASM) && !defined(FRODOKEM_HAVE_NEON_RUNTIME)
    frodokem_mul_add_sb_plus_e_arm(out, b, s, n, qmask);
#else
#ifdef FRODOKEM_HAVE_NEON_RUNTIME
    if (IS_AARCH64_ASIMD(cpuid_flags)) {
        frodokem_mul_add_sb_plus_e_arm(out, b, s, n, qmask);
    }
    else
#endif
#ifdef FRODOKEM_HAVE_MATRIX_ASM_AVX512
    if (IS_INTEL_AVX512(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        frodokem_mul_add_sb_plus_e_avx512(out, b, s, n, qmask);
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
#ifdef FRODOKEM_HAVE_MATRIX_ASM
    if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        frodokem_mul_add_sb_plus_e_avx2(out, b, s, n, qmask);
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
    {
#ifdef WOLFSSL_FRODOKEM_SMALL
    int i;
    int j;
    int k;

    /* Keep FRODOKEM_NBAR accumulators per row of S (one per output column), as
     * in the FrodoKEM reference: the inner loop then reads a contiguous row of
     * B (b[j*nbar + 0..nbar)) and reuses the single S coefficient, which is
     * cache-friendly and lets the compiler vectorize the nbar-wide update.
     * Accumulation order per output element is unchanged, so results match. */
    for (i = 0; i < FRODOKEM_NBAR; i++) {
        word16 acc[FRODOKEM_NBAR];
        const word16* sRow = s + i * n;

        for (k = 0; k < FRODOKEM_NBAR; k++) {
            acc[k] = out[i * FRODOKEM_NBAR + k];
        }
        for (j = 0; j < n; j++) {
            word16 sij = sRow[j];
            const word16* bRow = b + j * FRODOKEM_NBAR;

            for (k = 0; k < FRODOKEM_NBAR; k++) {
                acc[k] = (word16)(acc[k] + sij * bRow[k]);
            }
        }
        for (k = 0; k < FRODOKEM_NBAR; k++) {
            out[i * FRODOKEM_NBAR + k] = (word16)(acc[k] & qmask);
        }
    }
#else
#if FRODOKEM_NBAR != 8
    #error "Unrolled frodokem_mul_add_sb_plus_e assumes FRODOKEM_NBAR == 8."
#endif
    int j;
    const word16* s0 = s;
    const word16* s1 = s + n;
    const word16* s2 = s + 2 * n;
    const word16* s3 = s + 3 * n;
    const word16* s4 = s + 4 * n;
    const word16* s5 = s + 5 * n;
    const word16* s6 = s + 6 * n;
    const word16* s7 = s + 7 * n;

    /* out holds E on entry. Both nbar dimensions are fully unrolled, leaving
     * only the loop over n; each B row is loaded once and reused across all 8
     * output rows. Accumulate directly into out - the word16 stores wrap mod
     * 2^16, the final reduction for q == 2^16 (976/1344). For q == 2^15 (640)
     * one &qMask pass at the very end reduces mod q (q divides 2^16). */
    for (j = 0; j < n; j++) {
        const word16* bRow = b + j * FRODOKEM_NBAR;
        word16 b0 = bRow[0];
        word16 b1 = bRow[1];
        word16 b2 = bRow[2];
        word16 b3 = bRow[3];
        word16 b4 = bRow[4];
        word16 b5 = bRow[5];
        word16 b6 = bRow[6];
        word16 b7 = bRow[7];
        word16 sij;

        sij = s0[j];
        out[0]  = (word16)(out[0]  + sij * b0);
        out[1]  = (word16)(out[1]  + sij * b1);
        out[2]  = (word16)(out[2]  + sij * b2);
        out[3]  = (word16)(out[3]  + sij * b3);
        out[4]  = (word16)(out[4]  + sij * b4);
        out[5]  = (word16)(out[5]  + sij * b5);
        out[6]  = (word16)(out[6]  + sij * b6);
        out[7]  = (word16)(out[7]  + sij * b7);
        sij = s1[j];
        out[8]  = (word16)(out[8]  + sij * b0);
        out[9]  = (word16)(out[9]  + sij * b1);
        out[10] = (word16)(out[10] + sij * b2);
        out[11] = (word16)(out[11] + sij * b3);
        out[12] = (word16)(out[12] + sij * b4);
        out[13] = (word16)(out[13] + sij * b5);
        out[14] = (word16)(out[14] + sij * b6);
        out[15] = (word16)(out[15] + sij * b7);
        sij = s2[j];
        out[16] = (word16)(out[16] + sij * b0);
        out[17] = (word16)(out[17] + sij * b1);
        out[18] = (word16)(out[18] + sij * b2);
        out[19] = (word16)(out[19] + sij * b3);
        out[20] = (word16)(out[20] + sij * b4);
        out[21] = (word16)(out[21] + sij * b5);
        out[22] = (word16)(out[22] + sij * b6);
        out[23] = (word16)(out[23] + sij * b7);
        sij = s3[j];
        out[24] = (word16)(out[24] + sij * b0);
        out[25] = (word16)(out[25] + sij * b1);
        out[26] = (word16)(out[26] + sij * b2);
        out[27] = (word16)(out[27] + sij * b3);
        out[28] = (word16)(out[28] + sij * b4);
        out[29] = (word16)(out[29] + sij * b5);
        out[30] = (word16)(out[30] + sij * b6);
        out[31] = (word16)(out[31] + sij * b7);
        sij = s4[j];
        out[32] = (word16)(out[32] + sij * b0);
        out[33] = (word16)(out[33] + sij * b1);
        out[34] = (word16)(out[34] + sij * b2);
        out[35] = (word16)(out[35] + sij * b3);
        out[36] = (word16)(out[36] + sij * b4);
        out[37] = (word16)(out[37] + sij * b5);
        out[38] = (word16)(out[38] + sij * b6);
        out[39] = (word16)(out[39] + sij * b7);
        sij = s5[j];
        out[40] = (word16)(out[40] + sij * b0);
        out[41] = (word16)(out[41] + sij * b1);
        out[42] = (word16)(out[42] + sij * b2);
        out[43] = (word16)(out[43] + sij * b3);
        out[44] = (word16)(out[44] + sij * b4);
        out[45] = (word16)(out[45] + sij * b5);
        out[46] = (word16)(out[46] + sij * b6);
        out[47] = (word16)(out[47] + sij * b7);
        sij = s6[j];
        out[48] = (word16)(out[48] + sij * b0);
        out[49] = (word16)(out[49] + sij * b1);
        out[50] = (word16)(out[50] + sij * b2);
        out[51] = (word16)(out[51] + sij * b3);
        out[52] = (word16)(out[52] + sij * b4);
        out[53] = (word16)(out[53] + sij * b5);
        out[54] = (word16)(out[54] + sij * b6);
        out[55] = (word16)(out[55] + sij * b7);
        sij = s7[j];
        out[56] = (word16)(out[56] + sij * b0);
        out[57] = (word16)(out[57] + sij * b1);
        out[58] = (word16)(out[58] + sij * b2);
        out[59] = (word16)(out[59] + sij * b3);
        out[60] = (word16)(out[60] + sij * b4);
        out[61] = (word16)(out[61] + sij * b5);
        out[62] = (word16)(out[62] + sij * b6);
        out[63] = (word16)(out[63] + sij * b7);
    }

#ifdef FRODOKEM_D15_SHAKE128
    /* q == 2^15 (640) needs a final reduction mod q; for q == 2^16 (976/1344)
     * the word16 stores already reduced, so no mask. */
#ifdef FRODOKEM_D16_SHAKE256
    if (qmask != 0xffff)
#endif
    {
        out[0] = (word16)(out[0] & qmask);
        out[1] = (word16)(out[1] & qmask);
        out[2] = (word16)(out[2] & qmask);
        out[3] = (word16)(out[3] & qmask);
        out[4] = (word16)(out[4] & qmask);
        out[5] = (word16)(out[5] & qmask);
        out[6] = (word16)(out[6] & qmask);
        out[7] = (word16)(out[7] & qmask);
        out[8] = (word16)(out[8] & qmask);
        out[9] = (word16)(out[9] & qmask);
        out[10] = (word16)(out[10] & qmask);
        out[11] = (word16)(out[11] & qmask);
        out[12] = (word16)(out[12] & qmask);
        out[13] = (word16)(out[13] & qmask);
        out[14] = (word16)(out[14] & qmask);
        out[15] = (word16)(out[15] & qmask);
        out[16] = (word16)(out[16] & qmask);
        out[17] = (word16)(out[17] & qmask);
        out[18] = (word16)(out[18] & qmask);
        out[19] = (word16)(out[19] & qmask);
        out[20] = (word16)(out[20] & qmask);
        out[21] = (word16)(out[21] & qmask);
        out[22] = (word16)(out[22] & qmask);
        out[23] = (word16)(out[23] & qmask);
        out[24] = (word16)(out[24] & qmask);
        out[25] = (word16)(out[25] & qmask);
        out[26] = (word16)(out[26] & qmask);
        out[27] = (word16)(out[27] & qmask);
        out[28] = (word16)(out[28] & qmask);
        out[29] = (word16)(out[29] & qmask);
        out[30] = (word16)(out[30] & qmask);
        out[31] = (word16)(out[31] & qmask);
        out[32] = (word16)(out[32] & qmask);
        out[33] = (word16)(out[33] & qmask);
        out[34] = (word16)(out[34] & qmask);
        out[35] = (word16)(out[35] & qmask);
        out[36] = (word16)(out[36] & qmask);
        out[37] = (word16)(out[37] & qmask);
        out[38] = (word16)(out[38] & qmask);
        out[39] = (word16)(out[39] & qmask);
        out[40] = (word16)(out[40] & qmask);
        out[41] = (word16)(out[41] & qmask);
        out[42] = (word16)(out[42] & qmask);
        out[43] = (word16)(out[43] & qmask);
        out[44] = (word16)(out[44] & qmask);
        out[45] = (word16)(out[45] & qmask);
        out[46] = (word16)(out[46] & qmask);
        out[47] = (word16)(out[47] & qmask);
        out[48] = (word16)(out[48] & qmask);
        out[49] = (word16)(out[49] & qmask);
        out[50] = (word16)(out[50] & qmask);
        out[51] = (word16)(out[51] & qmask);
        out[52] = (word16)(out[52] & qmask);
        out[53] = (word16)(out[53] & qmask);
        out[54] = (word16)(out[54] & qmask);
        out[55] = (word16)(out[55] & qmask);
        out[56] = (word16)(out[56] & qmask);
        out[57] = (word16)(out[57] & qmask);
        out[58] = (word16)(out[58] & qmask);
        out[59] = (word16)(out[59] & qmask);
        out[60] = (word16)(out[60] & qmask);
        out[61] = (word16)(out[61] & qmask);
        out[62] = (word16)(out[62] & qmask);
        out[63] = (word16)(out[63] & qmask);
    }
#else
    (void)qmask;
#endif /* FRODOKEM_D15_SHAKE128 */
#endif /* WOLFSSL_FRODOKEM_SMALL */
    }
#endif /* FRODOKEM_HAVE_ARM_ASM */
}

/* Compute out = B * S where B is nbar x n and S (supplied as S^T, nbar x n)
 * is n x nbar.
 *
 * @param  [out]  out  Output matrix (nbar * nbar, row-major).
 * @param  [in]   b      Matrix B (nbar * n, row-major).
 * @param  [in]   s      Secret matrix S^T (nbar * n, row-major).
 * @param  [in]   n      Matrix dimension n.
 * @param  [in]   qmask  Reduction mask (q - 1).
 */
void frodokem_mul_bs(word16* out, const word16* b, const word16* s,
    int n, int qmask)
{
#ifdef FRODOKEM_HAVE_SME
    /* SME computes the whole nbar x nbar tile with the ZA UMOPA, but needs B
     * and S in the interleaved MOPA layout, so transpose into scratch first.
     * Falls through to SVE/NEON/C if SME is absent or scratch cannot be had. */
    word16* bt = NULL;
    word16* st = NULL;
    int sme = 0;

    if (frodokem_sme_svl_ok) {
        size_t sz = (size_t)FRODOKEM_NBAR * (size_t)n * sizeof(word16);
        bt = (word16*)XMALLOC(sz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        st = (word16*)XMALLOC(sz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if ((bt != NULL) && (st != NULL)) {
            frodokem_sme_interleave(bt, b, FRODOKEM_NBAR, n);
            frodokem_sme_interleave(st, s, FRODOKEM_NBAR, n);
            frodokem_mul_bs_sme(out, bt, st, n, qmask);
            sme = 1;
        }
    }
    if (!sme)
#endif /* FRODOKEM_HAVE_SME */
    {
#if defined(FRODOKEM_HAVE_ARM_ASM) && !defined(FRODOKEM_HAVE_NEON_RUNTIME)
    frodokem_mul_bs_arm(out, b, s, n, qmask);
#else
#ifdef FRODOKEM_HAVE_SVE
    if (IS_AARCH64_SVE(cpuid_flags)) {
        frodokem_mul_bs_sve(out, b, s, n, qmask);
    }
    else
#endif
#ifdef FRODOKEM_HAVE_NEON_RUNTIME
    if (IS_AARCH64_ASIMD(cpuid_flags)) {
        frodokem_mul_bs_arm(out, b, s, n, qmask);
    }
    else
#endif
#ifdef FRODOKEM_HAVE_MATRIX_ASM_AVX512
    if (IS_INTEL_AVX512(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        frodokem_mul_bs_avx512(out, b, s, n, qmask);
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
#ifdef FRODOKEM_HAVE_MATRIX_ASM
    if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        frodokem_mul_bs_avx2(out, b, s, n, qmask);
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
    {
#ifdef WOLFSSL_FRODOKEM_SMALL
    int i;
    int j;
    int k;

    for (i = 0; i < FRODOKEM_NBAR; i++) {
        for (k = 0; k < FRODOKEM_NBAR; k++) {
            word16 acc = 0;
            /* column k of S == row k of S^T. */
            const word16* sCol = s + k * n;

            for (j = 0; j < n; j++) {
                acc = (word16)(acc + b[i * n + j] * sCol[j]);
            }
            out[i * FRODOKEM_NBAR + k] = (word16)(acc & qmask);
        }
    }
#else
#if FRODOKEM_NBAR != 8
    #error "Unrolled frodokem_mul_bs assumes FRODOKEM_NBAR == 8."
#endif
    int j;
    const word16* b0 = b;
    const word16* b1 = b + n;
    const word16* b2 = b + 2 * n;
    const word16* b3 = b + 3 * n;
    const word16* b4 = b + 4 * n;
    const word16* b5 = b + 5 * n;
    const word16* b6 = b + 6 * n;
    const word16* b7 = b + 7 * n;
    const word16* s0 = s;
    const word16* s1 = s + n;
    const word16* s2 = s + 2 * n;
    const word16* s3 = s + 3 * n;
    const word16* s4 = s + 4 * n;
    const word16* s5 = s + 5 * n;
    const word16* s6 = s + 6 * n;
    const word16* s7 = s + 7 * n;

    XMEMSET(out, 0, sizeof(word16) * FRODOKEM_NBAR_SQ);

    /* Both nbar dimensions are fully unrolled, leaving only the loop over n.
     * Each row of B and column of S (row of S^T) is loaded once per j and
     * combined as an outer product accumulated into out. The word16 stores
     * wrap mod 2^16, the final reduction for q == 2^16 (976/1344). For
     * q == 2^15 (640) one &qMask pass at the very end reduces mod q (q
     * divides 2^16). */
    for (j = 0; j < n; j++) {
        word16 sc0 = s0[j];
        word16 sc1 = s1[j];
        word16 sc2 = s2[j];
        word16 sc3 = s3[j];
        word16 sc4 = s4[j];
        word16 sc5 = s5[j];
        word16 sc6 = s6[j];
        word16 sc7 = s7[j];
        word16 bij;

        bij = b0[j];
        out[0]  = (word16)(out[0]  + bij * sc0);
        out[1]  = (word16)(out[1]  + bij * sc1);
        out[2]  = (word16)(out[2]  + bij * sc2);
        out[3]  = (word16)(out[3]  + bij * sc3);
        out[4]  = (word16)(out[4]  + bij * sc4);
        out[5]  = (word16)(out[5]  + bij * sc5);
        out[6]  = (word16)(out[6]  + bij * sc6);
        out[7]  = (word16)(out[7]  + bij * sc7);
        bij = b1[j];
        out[8]  = (word16)(out[8]  + bij * sc0);
        out[9]  = (word16)(out[9]  + bij * sc1);
        out[10] = (word16)(out[10] + bij * sc2);
        out[11] = (word16)(out[11] + bij * sc3);
        out[12] = (word16)(out[12] + bij * sc4);
        out[13] = (word16)(out[13] + bij * sc5);
        out[14] = (word16)(out[14] + bij * sc6);
        out[15] = (word16)(out[15] + bij * sc7);
        bij = b2[j];
        out[16] = (word16)(out[16] + bij * sc0);
        out[17] = (word16)(out[17] + bij * sc1);
        out[18] = (word16)(out[18] + bij * sc2);
        out[19] = (word16)(out[19] + bij * sc3);
        out[20] = (word16)(out[20] + bij * sc4);
        out[21] = (word16)(out[21] + bij * sc5);
        out[22] = (word16)(out[22] + bij * sc6);
        out[23] = (word16)(out[23] + bij * sc7);
        bij = b3[j];
        out[24] = (word16)(out[24] + bij * sc0);
        out[25] = (word16)(out[25] + bij * sc1);
        out[26] = (word16)(out[26] + bij * sc2);
        out[27] = (word16)(out[27] + bij * sc3);
        out[28] = (word16)(out[28] + bij * sc4);
        out[29] = (word16)(out[29] + bij * sc5);
        out[30] = (word16)(out[30] + bij * sc6);
        out[31] = (word16)(out[31] + bij * sc7);
        bij = b4[j];
        out[32] = (word16)(out[32] + bij * sc0);
        out[33] = (word16)(out[33] + bij * sc1);
        out[34] = (word16)(out[34] + bij * sc2);
        out[35] = (word16)(out[35] + bij * sc3);
        out[36] = (word16)(out[36] + bij * sc4);
        out[37] = (word16)(out[37] + bij * sc5);
        out[38] = (word16)(out[38] + bij * sc6);
        out[39] = (word16)(out[39] + bij * sc7);
        bij = b5[j];
        out[40] = (word16)(out[40] + bij * sc0);
        out[41] = (word16)(out[41] + bij * sc1);
        out[42] = (word16)(out[42] + bij * sc2);
        out[43] = (word16)(out[43] + bij * sc3);
        out[44] = (word16)(out[44] + bij * sc4);
        out[45] = (word16)(out[45] + bij * sc5);
        out[46] = (word16)(out[46] + bij * sc6);
        out[47] = (word16)(out[47] + bij * sc7);
        bij = b6[j];
        out[48] = (word16)(out[48] + bij * sc0);
        out[49] = (word16)(out[49] + bij * sc1);
        out[50] = (word16)(out[50] + bij * sc2);
        out[51] = (word16)(out[51] + bij * sc3);
        out[52] = (word16)(out[52] + bij * sc4);
        out[53] = (word16)(out[53] + bij * sc5);
        out[54] = (word16)(out[54] + bij * sc6);
        out[55] = (word16)(out[55] + bij * sc7);
        bij = b7[j];
        out[56] = (word16)(out[56] + bij * sc0);
        out[57] = (word16)(out[57] + bij * sc1);
        out[58] = (word16)(out[58] + bij * sc2);
        out[59] = (word16)(out[59] + bij * sc3);
        out[60] = (word16)(out[60] + bij * sc4);
        out[61] = (word16)(out[61] + bij * sc5);
        out[62] = (word16)(out[62] + bij * sc6);
        out[63] = (word16)(out[63] + bij * sc7);
    }

#ifdef FRODOKEM_D15_SHAKE128
    /* q == 2^15 (640) needs a final reduction mod q; for q == 2^16 (976/1344)
     * the word16 stores already reduced, so no mask. */
#ifdef FRODOKEM_D16_SHAKE256
    if (qmask != 0xffff)
#endif
    {
        out[0] = (word16)(out[0] & qmask);
        out[1] = (word16)(out[1] & qmask);
        out[2] = (word16)(out[2] & qmask);
        out[3] = (word16)(out[3] & qmask);
        out[4] = (word16)(out[4] & qmask);
        out[5] = (word16)(out[5] & qmask);
        out[6] = (word16)(out[6] & qmask);
        out[7] = (word16)(out[7] & qmask);
        out[8] = (word16)(out[8] & qmask);
        out[9] = (word16)(out[9] & qmask);
        out[10] = (word16)(out[10] & qmask);
        out[11] = (word16)(out[11] & qmask);
        out[12] = (word16)(out[12] & qmask);
        out[13] = (word16)(out[13] & qmask);
        out[14] = (word16)(out[14] & qmask);
        out[15] = (word16)(out[15] & qmask);
        out[16] = (word16)(out[16] & qmask);
        out[17] = (word16)(out[17] & qmask);
        out[18] = (word16)(out[18] & qmask);
        out[19] = (word16)(out[19] & qmask);
        out[20] = (word16)(out[20] & qmask);
        out[21] = (word16)(out[21] & qmask);
        out[22] = (word16)(out[22] & qmask);
        out[23] = (word16)(out[23] & qmask);
        out[24] = (word16)(out[24] & qmask);
        out[25] = (word16)(out[25] & qmask);
        out[26] = (word16)(out[26] & qmask);
        out[27] = (word16)(out[27] & qmask);
        out[28] = (word16)(out[28] & qmask);
        out[29] = (word16)(out[29] & qmask);
        out[30] = (word16)(out[30] & qmask);
        out[31] = (word16)(out[31] & qmask);
        out[32] = (word16)(out[32] & qmask);
        out[33] = (word16)(out[33] & qmask);
        out[34] = (word16)(out[34] & qmask);
        out[35] = (word16)(out[35] & qmask);
        out[36] = (word16)(out[36] & qmask);
        out[37] = (word16)(out[37] & qmask);
        out[38] = (word16)(out[38] & qmask);
        out[39] = (word16)(out[39] & qmask);
        out[40] = (word16)(out[40] & qmask);
        out[41] = (word16)(out[41] & qmask);
        out[42] = (word16)(out[42] & qmask);
        out[43] = (word16)(out[43] & qmask);
        out[44] = (word16)(out[44] & qmask);
        out[45] = (word16)(out[45] & qmask);
        out[46] = (word16)(out[46] & qmask);
        out[47] = (word16)(out[47] & qmask);
        out[48] = (word16)(out[48] & qmask);
        out[49] = (word16)(out[49] & qmask);
        out[50] = (word16)(out[50] & qmask);
        out[51] = (word16)(out[51] & qmask);
        out[52] = (word16)(out[52] & qmask);
        out[53] = (word16)(out[53] & qmask);
        out[54] = (word16)(out[54] & qmask);
        out[55] = (word16)(out[55] & qmask);
        out[56] = (word16)(out[56] & qmask);
        out[57] = (word16)(out[57] & qmask);
        out[58] = (word16)(out[58] & qmask);
        out[59] = (word16)(out[59] & qmask);
        out[60] = (word16)(out[60] & qmask);
        out[61] = (word16)(out[61] & qmask);
        out[62] = (word16)(out[62] & qmask);
        out[63] = (word16)(out[63] & qmask);
    }
#else
    (void)qmask;
#endif /* FRODOKEM_D15_SHAKE128 */
#endif /* WOLFSSL_FRODOKEM_SMALL */
    }
#endif /* FRODOKEM_HAVE_ARM_ASM */
    }
#ifdef FRODOKEM_HAVE_SME
    /* st held the interleaved secret matrix S^T; bt is the public B matrix. */
    if (st != NULL) {
        ForceZero(st, (size_t)FRODOKEM_NBAR * (size_t)n * sizeof(word16));
    }
    XFREE(bt, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(st, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif /* FRODOKEM_HAVE_SME */
}

/* Add matrix b into matrix a modulo q, element-wise (nbar x nbar).
 *
 * Used to form C = V + Encode(u): a is V (updated in place), b is Encode(u).
 *
 * @param  [in, out]  a      Matrix accumulated into (nbar * nbar, row-major).
 * @param  [in]       b      Matrix added to a (nbar * nbar, row-major).
 * @param  [in]       qmask  Reduction mask (q - 1).
 */
void frodokem_add(word16* a, const word16* b, int qmask)
{
#if defined(FRODOKEM_HAVE_ARM_ASM) && !defined(FRODOKEM_HAVE_NEON_RUNTIME)
    frodokem_add_arm(a, b, qmask);
#else
#ifdef FRODOKEM_HAVE_SVE
    if (IS_AARCH64_SVE(cpuid_flags)) {
        frodokem_add_sve(a, b, qmask);
    }
    else
#endif
#ifdef FRODOKEM_HAVE_NEON_RUNTIME
    if (IS_AARCH64_ASIMD(cpuid_flags)) {
        frodokem_add_arm(a, b, qmask);
    }
    else
#endif
#ifdef FRODOKEM_HAVE_MATRIX_ASM_AVX512
    if (IS_INTEL_AVX512(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        frodokem_add_avx512(a, b, qmask);
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
#ifdef FRODOKEM_HAVE_MATRIX_ASM
    if (IS_INTEL_AVX2(cpuid_flags) && (SAVE_VECTOR_REGISTERS2() == 0)) {
        frodokem_add_avx2(a, b, qmask);
        RESTORE_VECTOR_REGISTERS();
    }
    else
#endif
    {
#ifdef WOLFSSL_FRODOKEM_SMALL
    int i;

    for (i = 0; i < FRODOKEM_NBAR_SQ; i++) {
        a[i] = (word16)((a[i] + b[i]) & qmask);
    }
#else
#if FRODOKEM_NBAR_SQ != 64
    #error "Unrolled frodokem_add assumes FRODOKEM_NBAR_SQ == 64."
#endif
    /* nbar x nbar = FRODOKEM_NBAR_SQ (64) elements; the i loop is fully
     * unrolled. word16 stores wrap mod 2^16, the reduction for q == 2^16
     * (976/1344). */
    a[0] = (word16)(a[0] + b[0]);
    a[1] = (word16)(a[1] + b[1]);
    a[2] = (word16)(a[2] + b[2]);
    a[3] = (word16)(a[3] + b[3]);
    a[4] = (word16)(a[4] + b[4]);
    a[5] = (word16)(a[5] + b[5]);
    a[6] = (word16)(a[6] + b[6]);
    a[7] = (word16)(a[7] + b[7]);
    a[8] = (word16)(a[8] + b[8]);
    a[9] = (word16)(a[9] + b[9]);
    a[10] = (word16)(a[10] + b[10]);
    a[11] = (word16)(a[11] + b[11]);
    a[12] = (word16)(a[12] + b[12]);
    a[13] = (word16)(a[13] + b[13]);
    a[14] = (word16)(a[14] + b[14]);
    a[15] = (word16)(a[15] + b[15]);
    a[16] = (word16)(a[16] + b[16]);
    a[17] = (word16)(a[17] + b[17]);
    a[18] = (word16)(a[18] + b[18]);
    a[19] = (word16)(a[19] + b[19]);
    a[20] = (word16)(a[20] + b[20]);
    a[21] = (word16)(a[21] + b[21]);
    a[22] = (word16)(a[22] + b[22]);
    a[23] = (word16)(a[23] + b[23]);
    a[24] = (word16)(a[24] + b[24]);
    a[25] = (word16)(a[25] + b[25]);
    a[26] = (word16)(a[26] + b[26]);
    a[27] = (word16)(a[27] + b[27]);
    a[28] = (word16)(a[28] + b[28]);
    a[29] = (word16)(a[29] + b[29]);
    a[30] = (word16)(a[30] + b[30]);
    a[31] = (word16)(a[31] + b[31]);
    a[32] = (word16)(a[32] + b[32]);
    a[33] = (word16)(a[33] + b[33]);
    a[34] = (word16)(a[34] + b[34]);
    a[35] = (word16)(a[35] + b[35]);
    a[36] = (word16)(a[36] + b[36]);
    a[37] = (word16)(a[37] + b[37]);
    a[38] = (word16)(a[38] + b[38]);
    a[39] = (word16)(a[39] + b[39]);
    a[40] = (word16)(a[40] + b[40]);
    a[41] = (word16)(a[41] + b[41]);
    a[42] = (word16)(a[42] + b[42]);
    a[43] = (word16)(a[43] + b[43]);
    a[44] = (word16)(a[44] + b[44]);
    a[45] = (word16)(a[45] + b[45]);
    a[46] = (word16)(a[46] + b[46]);
    a[47] = (word16)(a[47] + b[47]);
    a[48] = (word16)(a[48] + b[48]);
    a[49] = (word16)(a[49] + b[49]);
    a[50] = (word16)(a[50] + b[50]);
    a[51] = (word16)(a[51] + b[51]);
    a[52] = (word16)(a[52] + b[52]);
    a[53] = (word16)(a[53] + b[53]);
    a[54] = (word16)(a[54] + b[54]);
    a[55] = (word16)(a[55] + b[55]);
    a[56] = (word16)(a[56] + b[56]);
    a[57] = (word16)(a[57] + b[57]);
    a[58] = (word16)(a[58] + b[58]);
    a[59] = (word16)(a[59] + b[59]);
    a[60] = (word16)(a[60] + b[60]);
    a[61] = (word16)(a[61] + b[61]);
    a[62] = (word16)(a[62] + b[62]);
    a[63] = (word16)(a[63] + b[63]);

#ifdef FRODOKEM_D15_SHAKE128
    /* q == 2^15 (640) needs a final reduction mod q. */
#ifdef FRODOKEM_D16_SHAKE256
    if (qmask != 0xffff)
#endif
    {
        a[0] = (word16)(a[0] & qmask);
        a[1] = (word16)(a[1] & qmask);
        a[2] = (word16)(a[2] & qmask);
        a[3] = (word16)(a[3] & qmask);
        a[4] = (word16)(a[4] & qmask);
        a[5] = (word16)(a[5] & qmask);
        a[6] = (word16)(a[6] & qmask);
        a[7] = (word16)(a[7] & qmask);
        a[8] = (word16)(a[8] & qmask);
        a[9] = (word16)(a[9] & qmask);
        a[10] = (word16)(a[10] & qmask);
        a[11] = (word16)(a[11] & qmask);
        a[12] = (word16)(a[12] & qmask);
        a[13] = (word16)(a[13] & qmask);
        a[14] = (word16)(a[14] & qmask);
        a[15] = (word16)(a[15] & qmask);
        a[16] = (word16)(a[16] & qmask);
        a[17] = (word16)(a[17] & qmask);
        a[18] = (word16)(a[18] & qmask);
        a[19] = (word16)(a[19] & qmask);
        a[20] = (word16)(a[20] & qmask);
        a[21] = (word16)(a[21] & qmask);
        a[22] = (word16)(a[22] & qmask);
        a[23] = (word16)(a[23] & qmask);
        a[24] = (word16)(a[24] & qmask);
        a[25] = (word16)(a[25] & qmask);
        a[26] = (word16)(a[26] & qmask);
        a[27] = (word16)(a[27] & qmask);
        a[28] = (word16)(a[28] & qmask);
        a[29] = (word16)(a[29] & qmask);
        a[30] = (word16)(a[30] & qmask);
        a[31] = (word16)(a[31] & qmask);
        a[32] = (word16)(a[32] & qmask);
        a[33] = (word16)(a[33] & qmask);
        a[34] = (word16)(a[34] & qmask);
        a[35] = (word16)(a[35] & qmask);
        a[36] = (word16)(a[36] & qmask);
        a[37] = (word16)(a[37] & qmask);
        a[38] = (word16)(a[38] & qmask);
        a[39] = (word16)(a[39] & qmask);
        a[40] = (word16)(a[40] & qmask);
        a[41] = (word16)(a[41] & qmask);
        a[42] = (word16)(a[42] & qmask);
        a[43] = (word16)(a[43] & qmask);
        a[44] = (word16)(a[44] & qmask);
        a[45] = (word16)(a[45] & qmask);
        a[46] = (word16)(a[46] & qmask);
        a[47] = (word16)(a[47] & qmask);
        a[48] = (word16)(a[48] & qmask);
        a[49] = (word16)(a[49] & qmask);
        a[50] = (word16)(a[50] & qmask);
        a[51] = (word16)(a[51] & qmask);
        a[52] = (word16)(a[52] & qmask);
        a[53] = (word16)(a[53] & qmask);
        a[54] = (word16)(a[54] & qmask);
        a[55] = (word16)(a[55] & qmask);
        a[56] = (word16)(a[56] & qmask);
        a[57] = (word16)(a[57] & qmask);
        a[58] = (word16)(a[58] & qmask);
        a[59] = (word16)(a[59] & qmask);
        a[60] = (word16)(a[60] & qmask);
        a[61] = (word16)(a[61] & qmask);
        a[62] = (word16)(a[62] & qmask);
        a[63] = (word16)(a[63] & qmask);
    }
#else
    (void)qmask;
#endif /* FRODOKEM_D15_SHAKE128 */
#endif /* WOLFSSL_FRODOKEM_SMALL */
    }
#endif /* FRODOKEM_HAVE_ARM_ASM */
}

#endif /* WOLFSSL_HAVE_FRODOKEM */
