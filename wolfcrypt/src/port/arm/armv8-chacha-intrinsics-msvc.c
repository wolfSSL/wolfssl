/* armv8-chacha-intrinsics-msvc.c
 *
 * NEON C intrinsics implementation of the ARM64 ChaCha20 kernels, as a third
 * alternative to the GAS/inline-asm and armasm64 (.asm) forms wolfSSL already
 * ships. Opt-in behind WOLFSSL_ARMASM_INTRINSICS, so it never competes with the
 * armasm64 objects for symbols. See armv8-aes-intrinsics-msvc.c for rationale.
 *
 * SIBLING file (4th), like armv8-aes/sha/poly1305-intrinsics-msvc.c: upstream
 * generated sources are never edited in place.
 *
 * Verified against THREE references: the original inline asm (extracted
 * verbatim and built with clang-cl, since cl.exe cannot compile it), an
 * independent RFC 8439 pure-C oracle, and the published RFC 8439 section 2.4.2
 * vector -- plus a RAGGED MULTI-CALL streaming test, which is the only shape
 * that exercises the over/left leftover-keystream contract. THREE negative
 * controls proven RED first: a wrong rotation amount (7->6), never stashing the
 * leftover keystream, and skipping the block-counter increment.
 *
 * SCOPE: the four symbols wolfcrypt/src/chacha.c requires on ARM64 --
 * wc_chacha_setkey, wc_chacha_setiv, wc_chacha_use_over, wc_chacha_crypt_bytes.
 *
 * IMPLEMENTATION: FOUR-BLOCK-PARALLEL, like upstream's asm but expressed in
 * intrinsics rather than transliterated from its ~900 lines.
 *
 * HISTORY WORTH KEEPING: the first version did ONE block per iteration. It was
 * correct (same tests) but MEASURED SLOWER than wolfSSL's portable C -- 299 ms vs
 * 245 ms in an in-server A/B profile. One block at a time leaves a long
 * dependency chain of 16 NEON ops with nothing to interleave, while MSVC /O2
 * schedules the scalar C well. Rewriting to 4 blocks in parallel (each state word
 * broadcast across a vector, lane i = block i) restored the expected win:
 * microbenchmark 2.0x FASTER than wolfSSL C (0.128 s vs 0.257 s per 40x4 MiB,
 * checksums identical). The transposed layout also removes the vextq lane
 * rotations the single-block form needs for the diagonal rounds.
 *
 * LESSON: a faithful-but-narrow NEON port can lose to compiler-optimised scalar
 * code. Measure the kernel against the REAL fallback, not against a hand-written
 * baseline, and treat "slower than C" as a signal to widen the parallelism.
 *
 * THE SUBTLE PART is the leftover contract, read from chacha.c: after a call whose
 * length is not a multiple of 64, the unused keystream must be in ctx->over with
 * ctx->left = the number of unused bytes, because the NEXT call consumes them from
 * ((byte*)ctx->over) + CHACHA_CHUNK_BYTES - ctx->left. A single-shot test cannot
 * catch a bug here, which is why the Verification project drives a ragged
 * multi-call sequence (5,1,10,64,3,100,63,65,200,7 bytes).
 *
 * ChaCha20 is LITTLE-endian throughout (state words, counter, keystream) -- the
 * opposite of SHA-2. No byte swapping anywhere.
 */

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_ARMASM) && defined(WOLFSSL_ARMASM_INTRINSICS) && \
    defined(_MSC_VER) && !defined(__clang__) && \
    (defined(_M_ARM64) || defined(_M_ARM64EC)) && defined(HAVE_CHACHA)

#include <arm64_neon.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/chacha.h>
#include <string.h>


// The four ChaCha20 rotations. rotl16 has a cheaper form via a 16-bit reverse;
// the rest are shift-left OR'd with shift-right-and-insert.
static WC_INLINE uint32x4_t rotl16(uint32x4_t v) {
    return vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(v)));
}
static WC_INLINE uint32x4_t rotl12(uint32x4_t v) { return vsriq_n_u32(vshlq_n_u32(v, 12), v, 20); }
static WC_INLINE uint32x4_t rotl8 (uint32x4_t v) { return vsriq_n_u32(vshlq_n_u32(v,  8), v, 24); }
static WC_INLINE uint32x4_t rotl7 (uint32x4_t v) { return vsriq_n_u32(vshlq_n_u32(v,  7), v, 25); }

// One 64-byte ChaCha20 block from state x[16] into out[64].
static void chacha_block(const word32 x[16], byte out[64]) {
    uint32x4_t a = vld1q_u32(x + 0);
    uint32x4_t b = vld1q_u32(x + 4);
    uint32x4_t c = vld1q_u32(x + 8);
    uint32x4_t d = vld1q_u32(x + 12);
    const uint32x4_t a0 = a, b0 = b, c0 = c, d0 = d;

    for (int i = 0; i < 10; ++i) {
        // column round
        a = vaddq_u32(a, b); d = veorq_u32(d, a); d = rotl16(d);
        c = vaddq_u32(c, d); b = veorq_u32(b, c); b = rotl12(b);
        a = vaddq_u32(a, b); d = veorq_u32(d, a); d = rotl8(d);
        c = vaddq_u32(c, d); b = veorq_u32(b, c); b = rotl7(b);
        // diagonalise: b<<<1 lane, c<<<2, d<<<3
        b = vextq_u32(b, b, 1); c = vextq_u32(c, c, 2); d = vextq_u32(d, d, 3);
        // diagonal round
        a = vaddq_u32(a, b); d = veorq_u32(d, a); d = rotl16(d);
        c = vaddq_u32(c, d); b = veorq_u32(b, c); b = rotl12(b);
        a = vaddq_u32(a, b); d = veorq_u32(d, a); d = rotl8(d);
        c = vaddq_u32(c, d); b = veorq_u32(b, c); b = rotl7(b);
        // undiagonalise
        b = vextq_u32(b, b, 3); c = vextq_u32(c, c, 2); d = vextq_u32(d, d, 1);
    }

    a = vaddq_u32(a, a0); b = vaddq_u32(b, b0);
    c = vaddq_u32(c, c0); d = vaddq_u32(d, d0);

    vst1q_u8(out +  0, vreinterpretq_u8_u32(a));
    vst1q_u8(out + 16, vreinterpretq_u8_u32(b));
    vst1q_u8(out + 32, vreinterpretq_u8_u32(c));
    vst1q_u8(out + 48, vreinterpretq_u8_u32(d));
}


void wc_chacha_setkey(word32* x, const byte* key, word32 keySz) {
    // sigma constants: little-endian words of "expand 32-byte k"
    // (or "expand 16-byte k" for a 128-bit key, which also duplicates the key).
    if (keySz == 32) {
        x[0] = 0x61707865u; x[1] = 0x3320646eu;
        x[2] = 0x79622d32u; x[3] = 0x6b206574u;
    } else {
        x[0] = 0x61707865u; x[1] = 0x3120646eu;
        x[2] = 0x79622d36u; x[3] = 0x6b206574u;
    }
    for (int i = 0; i < 8; ++i) {
        const byte* p = (keySz == 32) ? (key + i * 4) : (key + (i % 4) * 4);
        x[4 + i] = (word32)p[0] | ((word32)p[1] << 8) |
                   ((word32)p[2] << 16) | ((word32)p[3] << 24);
    }
}

void wc_chacha_setiv(word32* x, const byte* iv, word32 counter) {
    x[12] = counter;
    for (int i = 0; i < 3; ++i) {
        const byte* p = iv + i * 4;
        x[13 + i] = (word32)p[0] | ((word32)p[1] << 8) |
                    ((word32)p[2] << 16) | ((word32)p[3] << 24);
    }
}

void wc_chacha_use_over(byte* over, byte* output, const byte* input,
    word32 len) {
    // Plain XOR of already-generated keystream. Must NOT touch ctx state --
    // chacha.c owns the left/pointer bookkeeping.
    for (word32 i = 0; i < len; ++i) output[i] = input[i] ^ over[i];
}

// FOUR-BLOCK-PARALLEL core.
//
// The single-block version was SLOWER than wolfSSL's portable C (measured: 299 ms
// vs 245 ms in-server). Root cause: one block at a time gives a long dependency
// chain of 16 NEON ops with nothing to interleave, while MSVC /O2 schedules the
// scalar C well. Upstream's asm avoids this by running FOUR blocks at once with
// each state word broadcast across a vector's 4 lanes -- lane i belongs to block
// i -- so a quarter-round is 4 independent quarter-rounds and there is no
// intra-vector shuffling in the round loop at all.
//
// That layout ("transposed" / SIMD-across-blocks) also removes the vextq lane
// rotations the single-block form needs for the diagonal rounds: the diagonal
// step just addresses different words, because words live in different registers
// rather than different lanes.
//
// 16 vectors of state, one per word; only the counter word differs per lane.
typedef struct { uint32x4_t w[16]; } State4;

/* C has no reference parameters, so this takes pointers (the Verification build
 * is C++ and used references; behaviour is identical). */
static WC_INLINE void qr4(uint32x4_t* a, uint32x4_t* b, uint32x4_t* c,
    uint32x4_t* d)
{
    *a = vaddq_u32(*a, *b); *d = veorq_u32(*d, *a); *d = rotl16(*d);
    *c = vaddq_u32(*c, *d); *b = veorq_u32(*b, *c); *b = rotl12(*b);
    *a = vaddq_u32(*a, *b); *d = veorq_u32(*d, *a); *d = rotl8(*d);
    *c = vaddq_u32(*c, *d); *b = veorq_u32(*b, *c); *b = rotl7(*b);
}

// Produce 4 x 64 bytes of keystream from base state x, counters x[12]+0..3.
static void chacha_4blocks(const word32 x[16], byte out[256]) {
    State4 s;
    for (int i = 0; i < 16; ++i) s.w[i] = vdupq_n_u32(x[i]);
    // per-lane counter: block j gets counter x[12]+j
    const uint32_t inc[4] = {0u, 1u, 2u, 3u};
    s.w[12] = vaddq_u32(s.w[12], vld1q_u32(inc));

    State4 in = s;
    for (int i = 0; i < 10; ++i) {
        qr4(&s.w[0], &s.w[4], &s.w[8], &s.w[12]);   // column
        qr4(&s.w[1], &s.w[5], &s.w[9], &s.w[13]);
        qr4(&s.w[2], &s.w[6], &s.w[10], &s.w[14]);
        qr4(&s.w[3], &s.w[7], &s.w[11], &s.w[15]);
        qr4(&s.w[0], &s.w[5], &s.w[10], &s.w[15]);   // diagonal -- no lane shuffles
        qr4(&s.w[1], &s.w[6], &s.w[11], &s.w[12]);
        qr4(&s.w[2], &s.w[7], &s.w[8], &s.w[13]);
        qr4(&s.w[3], &s.w[4], &s.w[9], &s.w[14]);
    }
    for (int i = 0; i < 16; ++i) s.w[i] = vaddq_u32(s.w[i], in.w[i]);

    // Untranspose: word i of block j is lane j of s.w[i]. Do it 4 words at a
    // time with the standard 4x4 32-bit transpose (trn + zip), matching what the
    // asm's trn1/trn2 pairs achieve.
    for (int g = 0; g < 4; ++g) {
        uint32x4_t r0 = s.w[g * 4 + 0], r1 = s.w[g * 4 + 1];
        uint32x4_t r2 = s.w[g * 4 + 2], r3 = s.w[g * 4 + 3];
        uint32x4x2_t t01 = vtrnq_u32(r0, r1);
        uint32x4x2_t t23 = vtrnq_u32(r2, r3);
        uint32x4_t b0 = vcombine_u32(vget_low_u32(t01.val[0]), vget_low_u32(t23.val[0]));
        uint32x4_t b1 = vcombine_u32(vget_low_u32(t01.val[1]), vget_low_u32(t23.val[1]));
        uint32x4_t b2 = vcombine_u32(vget_high_u32(t01.val[0]), vget_high_u32(t23.val[0]));
        uint32x4_t b3 = vcombine_u32(vget_high_u32(t01.val[1]), vget_high_u32(t23.val[1]));
        vst1q_u8(out +   0 + g * 16, vreinterpretq_u8_u32(b0));
        vst1q_u8(out +  64 + g * 16, vreinterpretq_u8_u32(b1));
        vst1q_u8(out + 128 + g * 16, vreinterpretq_u8_u32(b2));
        vst1q_u8(out + 192 + g * 16, vreinterpretq_u8_u32(b3));
    }
}


void wc_chacha_crypt_bytes(ChaCha* ctx, byte* c, const byte* m, word32 len) {
    byte ks[256];

    // Fast path: 4 blocks (256 B) at a time.
    while (len >= 256) {
        chacha_4blocks(ctx->X, ks);
        ctx->X[12] += 4;
        for (int i = 0; i < 256; i += 16) {
            vst1q_u8(c + i, veorq_u8(vld1q_u8(m + i), vld1q_u8(ks + i)));
        }
        m += 256; c += 256; len -= 256;
    }
    // 1..3 whole blocks
    while (len >= 64) {
        chacha_block(ctx->X, ks);
        ctx->X[12]++;
        for (int i = 0; i < 64; i += 16) {
            vst1q_u8(c + i, veorq_u8(vld1q_u8(m + i), vld1q_u8(ks + i)));
        }
        m += 64; c += 64; len -= 64;
    }
    if (len > 0) {
        // Partial tail. The leftover keystream must land in ctx->over with
        // ctx->left set, because chacha.c consumes it on the NEXT call from
        // ((byte*)ctx->over) + CHACHA_CHUNK_BYTES - ctx->left. Write the block
        // STRAIGHT into ctx->over (no separate 64-byte memcpy as in v1).
        chacha_block(ctx->X, (byte*)ctx->over);
        ctx->X[12]++;
        const byte* ks2 = (const byte*)ctx->over;
        for (word32 i = 0; i < len; ++i) c[i] = m[i] ^ ks2[i];
        ctx->left = 64 - len;
    } else {
        ctx->left = 0;
    }
}
#else

/* Keep the translation unit non-empty for compilers that reject empty objects. */
int armv8_chacha_intrinsics_msvc_not_used(void);
int armv8_chacha_intrinsics_msvc_not_used(void)
{
    return 0;
}

#endif /* WOLFSSL_ARMASM && real-MSVC ARM64 && HAVE_CHACHA */
