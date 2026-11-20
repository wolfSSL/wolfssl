/* armv8-sha-intrinsics-msvc.c
 *
 * NEON C intrinsics implementation of the ARM64 SHA-2 hardware-crypto kernels,
 * as a third alternative to the GAS/inline-asm and armasm64 (.asm) forms
 * wolfSSL already ships. Opt-in behind WOLFSSL_ARMASM_INTRINSICS, so it never
 * competes with the armasm64 objects for symbols. See the header comment in
 * armv8-aes-intrinsics-msvc.c for the rationale (build systems without an
 * ARM64 assembler step, e.g. CMake consumers).
 *
 * SIBLING file, like armv8-aes-intrinsics-msvc.c: the upstream generated sources
 * are never edited in place, so upstream regeneration stays clean.
 *
 * The kernel was proven against THREE independent references: the original
 * inline asm (extracted verbatim and built with clang-cl, since cl.exe cannot
 * compile it), an independent pure-C FIPS 180-4 oracle, and two published
 * FIPS 180-4 KATs. Both negative controls were proven RED first.
 *
 * SCOPE: SHA-256 is ACTIVE. SHA-512 is present but INTENTIONALLY INERT --
 * see the WOLFSSL_ARM64_SHA512_HW_MSVC block near the end of this file.
 *   - Transform_Sha256_Len_neon (the table/NEON non-crypto variant) is not
 *     ported; WOLFSSL_ARMASM_NO_NEON keeps that layer out.
 */

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_ARMASM) && defined(WOLFSSL_ARMASM_INTRINSICS) && \
    defined(_MSC_VER) && !defined(__clang__) && \
    (defined(_M_ARM64) || defined(_M_ARM64EC)) && \
    !defined(WOLFSSL_ARMASM_NO_HW_CRYPTO) && !defined(NO_SHA256)

#include <arm64_neon.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/sha256.h>

/* SHA-256 round constants K[0..63] (FIPS 180-4 section 4.2.2). Upstream holds
 * these in v8..v23 and loads them once outside the block loop; we mirror that. */
static const word32 L_SHA256_msvc_k[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
};

/* intrinsics for armv8-sha256-asm_c.c: lines 1042-1193
 * (Transform_Sha256_Len_crypto)
 *
 * SHA-256 compression over len/64 whole 64-byte blocks, using the ARMv8.0 SHA-2
 * crypto extensions. Structure taken from the asm:
 *   - digest a..h lives in v0,v1; v2,v3 keep the incoming copy for the
 *     Davies-Meyer feed-forward add.
 *   - the 16-word message schedule W lives in v4..v7 and is extended IN PLACE.
 *   - 16 rounds. Rounds 2..13 (1-based) extend the schedule first; rounds 1 and
 *     14..16 do not touch W.
 *
 * TWO NON-OBVIOUS POINTS, both of which produce a self-consistent but WRONG
 * digest if got wrong (each was caught by the published KAT during porting):
 *
 * 1. Schedule indexing. Round 2 in the asm is
 *      sha256su0 v4,v5 / add v24,v5,v9 / sha256su1 v4,v6,v7
 *    The register being UPDATED (v4) is NOT the register fed to the add (v5).
 *    Hence u0 = (r-1)%4 for the update while the add uses w[r%4].
 * 2. sha256h2 consumes the PRE-sha256h value of v0 (the asm's
 *    `mov v25.16b, v0.16b`), so it must be captured before vsha256hq_u32.
 *
 * The message is consumed BIG-ENDIAN, so each loaded vector is byte-reversed
 * (rev32 on the .16b view == vrev32q_u8 with a reinterpret round-trip). The
 * digest itself stays in host order.
 */
void Transform_Sha256_Len_crypto(wc_Sha256* sha256, const byte* data, word32 len)
{
    uint32x4_t k[16];
    uint32x4_t s0;
    uint32x4_t s1;
    word32 off;
    int i;

    for (i = 0; i < 16; i++) {
        k[i] = vld1q_u32(L_SHA256_msvc_k + i * 4);
    }

    s0 = vld1q_u32(sha256->digest);
    s1 = vld1q_u32(sha256->digest + 4);

    for (off = 0; off + WC_SHA256_BLOCK_SIZE <= len;
         off += WC_SHA256_BLOCK_SIZE) {
        uint32x4_t w[4];
        uint32x4_t in0;
        uint32x4_t in1;
        int r;

        for (i = 0; i < 4; i++) {
            w[i] = vreinterpretq_u32_u8(
                       vrev32q_u8(vld1q_u8(data + off + (word32)i * 16)));
        }

        in0 = s0;
        in1 = s1;

        for (r = 0; r < 16; r++) {
            uint32x4_t wk;
            uint32x4_t saved;

            if ((r >= 1) && (r <= 12)) {
                int u0 = (r - 1) % 4;   /* the W register being UPDATED */
                int u1 = r % 4;
                int u2 = (r + 1) % 4;
                int u3 = (r + 2) % 4;

                w[u0] = vsha256su0q_u32(w[u0], w[u1]);
                w[u0] = vsha256su1q_u32(w[u0], w[u2], w[u3]);
            }

            wk = vaddq_u32(w[r % 4], k[r]);

            saved = s0;                              /* mov v25.16b, v0.16b */
            s0 = vsha256hq_u32(s0, s1, wk);
            s1 = vsha256h2q_u32(s1, saved, wk);
        }

        s0 = vaddq_u32(s0, in0);
        s1 = vaddq_u32(s1, in1);
    }

    vst1q_u32(sha256->digest, s0);
    vst1q_u32(sha256->digest + 4, s1);
}

/* ==========================================================================
 * SHA-512 -- VERIFIED BUT INTENTIONALLY NOT ENABLED
 * ==========================================================================
 *
 * The kernel below is a complete, verified port of
 * Transform_Sha512_Len_crypto (armv8-sha512-asm_c.c). It was proven 4/4 against
 * the extracted original inline asm, an independent pure-C FIPS 180-4 oracle,
 * and the published FIPS 180-4 SHA-512("abc") vector; both negative controls
 * were proven RED first (dropping the 5th staging register; omitting the rev64
 * byte-swap).
 *
 * WHY IT IS STILL COMPILED OUT HERE:
 *
 * ARMv8.2-SHA512 is an OPTIONAL architectural extension, so unlike
 * AES/PMULL/SHA-256 it cannot be assumed present -- executing sha512h on a core
 * without it is an illegal instruction. It therefore needs a real runtime
 * feature gate, and sha512.c selects its transform at runtime through
 * Sha512_SetTransform() based on WOLFSSL_ARMASM_CRYPTO_SHA512 + cpuid_flags.
 *
 * wolfSSL's Windows-ARM64 cpuid path (cpuid.c, the _WIN32 branch) already
 * queries PF_ARM_SHA512_INSTRUCTIONS_AVAILABLE under
 * WOLFSSL_ARMASM_CRYPTO_SHA512, so the gate that was missing when this kernel
 * was written now exists upstream. Wiring this kernel to it should be
 * straightforward, but that has NOT been done or tested here -- the kernel has
 * only ever been exercised with the gate forced on, on a core that was
 * separately confirmed to execute vsha512hq_u64. Enabling it properly is left
 * as follow-up rather than shipped untested.
 *
 * For reference, x86-64 does NOT use hardware SHA-512 either: Intel SHA-NI
 * covers only SHA-1/SHA-256, so wolfSSL's x64 SHA-512 is an AVX1/AVX2 software
 * implementation with a four-way runtime downgrade.
 *
 * DO NOT define WOLFSSL_ARM64_SHA512_HW_MSVC without a working feature probe --
 * it will fault rather than fall back.
 */
#ifdef WOLFSSL_ARM64_SHA512_HW_MSVC

#include <wolfssl/wolfcrypt/sha512.h>

static const word64 L_SHA512_msvc_k[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
    0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
    0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
    0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
    0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
    0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
    0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
    0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
    0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
    0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
    0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
    0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
    0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
    0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

void Transform_Sha512_Len_crypto(wc_Sha512* sha512, const byte* data, word32 len)
{
#if defined(__aarch64__) || defined(_M_ARM64) || defined(_M_ARM64EC)
    /* FIVE-register rotation, derived mechanically from the asm (not guessed).
       Two earlier attempts modelled this as a FOUR-register (ab,cd,ef,gh)
       rotation and could never be right: the asm rotates v23..v27, where the
       extra register is a STAGING value produced by `add stg = cd + gh` in the
       middle of the round and which becomes the NEXT step's `ef`.

       Roles in the asm's step 1 (ab=v24 cd=v25 ef=v26 gh=v27 stg=v23):
         wk  = ext(W + K, 8)                    ; swap the doubleword pair
         t21 = ext(ef, gh, 8)
         t22 = ext(cd, ef, 8)
         gh  = gh + wk
         gh  = sha512h (gh, t21, t22)
         stg = cd + gh                          ; <-- the 5th register
         gh  = sha512h2(gh, cd, ab)
       Rotation into the next step, also derived:
         (ab, cd, ef, gh) <- (gh, ab, stg, ef)
       One step advances TWO SHA-512 rounds (each vector holds 2 words), so 40
       steps cover the 80 rounds. W cycles w[0..7]; K advances by one vector
       (2 constants) per step. */
    uint64x2_t ab = vld1q_u64(sha512->digest + 0);
    uint64x2_t cd = vld1q_u64(sha512->digest + 2);
    uint64x2_t ef = vld1q_u64(sha512->digest + 4);
    uint64x2_t gh = vld1q_u64(sha512->digest + 6);

    for (word32 off = 0; off + 128 <= len; off += 128) {
        uint64x2_t w[8];
        const uint64x2_t ab0 = ab, cd0 = cd, ef0 = ef, gh0 = gh;
        int i;
        int step;

        for (i = 0; i < 8; i++) {
            w[i] = vreinterpretq_u64_u8(
                       vrev64q_u8(vld1q_u8(data + off + (word32)i * 16)));
        }

        for (step = 0; step < 40; step++) {
            const int wi = step % 8;
            uint64x2_t wk, t21, t22, stg;

            /* From step 8 the asm interleaves the schedule update; expressed
               here as: refresh w[wi] before it is consumed, once past the first
               16 words (i.e. from step 8 on).
                 su0(w[i], w[i+1]) ; su1(w[i], w[i+7], ext(w[i+4], w[i+5], 8)) */
            if (step >= 8) {
                const int a1 = (wi + 1) % 8;
                const int a4 = (wi + 4) % 8;
                const int a5 = (wi + 5) % 8;
                const int a7 = (wi + 7) % 8;
                w[wi] = vsha512su0q_u64(w[wi], w[a1]);
                w[wi] = vsha512su1q_u64(w[wi], w[a7],
                                        vextq_u64(w[a4], w[a5], 1));
            }

            wk  = vaddq_u64(w[wi], vld1q_u64(L_SHA512_msvc_k + step * 2));
            wk  = vextq_u64(wk, wk, 1);          /* ext v20,v20,v20,#8 */

            t21 = vextq_u64(ef, gh, 1);
            t22 = vextq_u64(cd, ef, 1);

            gh  = vaddq_u64(gh, wk);
            gh  = vsha512hq_u64(gh, t21, t22);
            stg = vaddq_u64(cd, gh);             /* the 5th register */
            gh  = vsha512h2q_u64(gh, cd, ab);

            /* (ab, cd, ef, gh) <- (gh, ab, stg, ef) */
            {
                const uint64x2_t n_ab = gh;
                const uint64x2_t n_cd = ab;
                const uint64x2_t n_ef = stg;
                const uint64x2_t n_gh = ef;
                ab = n_ab; cd = n_cd; ef = n_ef; gh = n_gh;
            }
        }

        ab = vaddq_u64(ab, ab0);
        cd = vaddq_u64(cd, cd0);
        ef = vaddq_u64(ef, ef0);
        gh = vaddq_u64(gh, gh0);
    }

    vst1q_u64(sha512->digest + 0, ab);
    vst1q_u64(sha512->digest + 2, cd);
    vst1q_u64(sha512->digest + 4, ef);
    vst1q_u64(sha512->digest + 6, gh);
#else
    (void)sha512; (void)data; (void)len;
#endif
}

#endif /* WOLFSSL_ARM64_SHA512_HW_MSVC */

#else

/* Keep the translation unit non-empty for compilers that reject empty objects. */
int armv8_sha_intrinsics_msvc_not_used(void);
int armv8_sha_intrinsics_msvc_not_used(void)
{
    return 0;
}

#endif /* WOLFSSL_ARMASM && real-MSVC ARM64 && !NO_HW_CRYPTO && !NO_SHA256 */
