/* armv8-aes-intrinsics-msvc.c
 *
 * NEON C intrinsics implementation of the ARM64 AES/AES-GCM/AES-CBC crypto
 * kernels, as a THIRD alternative to the two forms wolfSSL already ships:
 *   - armv8-aes-asm.S / armv8-aes-asm_c.c  (GNU/GAS asm, GCC inline asm)
 *   - armv8-aes-asm.asm                    (Microsoft syntax, via armasm64.exe)
 *
 * The armasm64 route already covers MSVC ARM64 and is wired up in
 * wolfssl.vcxproj (WolfSSLAarch64Asm=true). This file does NOT replace it and
 * never competes with it for symbols: it is opt-in behind
 * WOLFSSL_ARMASM_INTRINSICS, which must be requested explicitly.
 *
 * Why a third form is useful: the armasm64 path needs a separate assembler
 * invocation, which in practice is wired up only through MSBuild
 * (.vcxproj CustomBuild rules). Projects that consume wolfSSL through CMake -
 * or any build system without an ARM64 assembler step - cannot use it as-is.
 * These intrinsics are compiled directly by cl.exe as ordinary C, so the ARM64
 * hardware-crypto path becomes available with no assembler step, no generated
 * .asm, and no per-source target-feature flag (MSVC enables NEON crypto
 * unconditionally on ARM64, unlike clang which needs -march=armv8-a+crypto).
 *
 * This is a SIBLING file: the generated sources are never edited in place, so
 * upstream regeneration stays clean.
 *
 * Each kernel was proven byte-identical to the original inline asm and to
 * independent pure-C oracles and published KATs; see the PR description.
 *
 * SCOPE: the 19 hardware-crypto *_AARCH64 kernels that wolfcrypt/src/aes.c
 * references, plus 7 software-fallback symbols it links unconditionally (see
 * the "Base software-fallback layer" section at the end of this file), 26 total.
 *
 * Setup / control / finalize path: AES_set_key_AARCH64, AES_encrypt_AARCH64,
 * AES_decrypt_AARCH64, AES_CBC_encrypt_AARCH64, AES_CBC_decrypt_AARCH64,
 * AES_GCM_ghash_block_AARCH64 (the GHASH hot spot), AES_GCM_set_key_AARCH64,
 * AES_GCM_init_AARCH64, AES_GCM_aad_update_AARCH64, AES_GCM_encrypt_block_AARCH64,
 * AES_GCM_encrypt_final_AARCH64, AES_GCM_decrypt_final_AARCH64.
 *
 * Data path: AES_encrypt_blocks_AARCH64, AES_decrypt_blocks_AARCH64 (ECB),
 * AES_CTR_encrypt_AARCH64, AES_GCM_encrypt_AARCH64, AES_GCM_decrypt_AARCH64
 * (one-shot), AES_GCM_encrypt_update_AARCH64, AES_GCM_decrypt_update_AARCH64
 * (streaming). These are re-expressed as clear loops over the verified
 * primitives rather than reproducing the asm's 8-block unrolling and H^2..H^8
 * GHASH ladder — semantics preserved, not the asm's instruction schedule.
 *
 * NOT YET PORTED: AES_XTS_* (WOLFSSL_AES_XTS) and all _EOR3 variants
 * (WOLFSSL_ARMASM_CRYPTO_SHA3). Neither was enabled in the configuration this
 * was developed against, so aes.c never referenced them. Enabling either
 * alongside WOLFSSL_ARMASM_INTRINSICS will not link; the armasm64 path should
 * be used for those configurations until they are added.
 */

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_ARMASM) && defined(WOLFSSL_ARMASM_INTRINSICS) && \
    defined(_MSC_VER) && !defined(__clang__) && \
    (defined(_M_ARM64) || defined(_M_ARM64EC)) && \
    !defined(WOLFSSL_ARMASM_NO_HW_CRYPTO)

#include <arm64_neon.h>
#include <intrin.h>     /* _byteswap_ulong / _byteswap_uint64 */
#include <string.h>
#include <wolfssl/wolfcrypt/types.h>

/* intrinsics for armv8-aes-asm_c.c: lines 37-583 (AES_set_key_AARCH64)
 *
 * Standard AES (Rijndael) key expansion. SubWord uses the AES instruction as the
 * asm does: aese on a 4-lane broadcast of the source word (with a zero round
 * key) performs SubBytes; the asm then rotates the lane-0 result by 8. For the
 * word-0-of-group step, that ror folds in RotWord. For dir=decrypt, the schedule
 * is reversed (round key r <-> Nr-r) with InvMixColumns (aesimc) on the middle
 * keys — the equivalent-inverse-cipher schedule consumed by aesd/aesimc. */
static WC_INLINE word32 AES_sub_word_ror8(word32 w)
{
    uint8x16_t z = vdupq_n_u8(0);
    uint8x16_t in = vreinterpretq_u8_u32(vdupq_n_u32(w));
    word32 sub = vgetq_lane_u32(vreinterpretq_u32_u8(vaeseq_u8(z, in)), 0);
    return (sub >> 8) | (sub << 24);
}

void AES_set_key_AARCH64(const byte* userKey, int keylen, byte* key, int dir)
{
    const int Nk = keylen / 4;
    const int Nr = Nk + 6;
    const int total = 4 * (Nr + 1);
    word32* w = (word32*)key;
    word32 rcon = 1;
    int i;

    for (i = 0; i < Nk; i++) {
        word32 v;
        memcpy(&v, userKey + i * 4, 4);
        w[i] = v;
    }
    for (i = Nk; i < total; i++) {
        word32 t = w[i - 1];
        if (i % Nk == 0) {
            word32 hi;
            t = AES_sub_word_ror8(t) ^ rcon;
            hi = rcon & 0x80;
            rcon = (rcon << 1) & 0xff;
            if (hi) rcon ^= 0x1b;
        }
        else if (Nk > 6 && (i % Nk) == 4) {
            uint8x16_t z = vdupq_n_u8(0);
            uint8x16_t in = vreinterpretq_u8_u32(vdupq_n_u32(t));
            t = vgetq_lane_u32(vreinterpretq_u32_u8(vaeseq_u8(z, in)), 0);
        }
        w[i] = w[i - Nk] ^ t;
    }

    if (dir != 0) {
        int r;
        for (r = 0; r <= Nr / 2; r++) {
            int s = Nr - r;
            uint8x16_t a = vld1q_u8(key + r * 16);
            uint8x16_t b = vld1q_u8(key + s * 16);
            uint8x16_t na = (s == 0 || s == Nr) ? b : vaesimcq_u8(b);
            uint8x16_t nb = (r == 0 || r == Nr) ? a : vaesimcq_u8(a);
            vst1q_u8(key + r * 16, na);
            if (s != r) vst1q_u8(key + s * 16, nb);
        }
    }
}

/* intrinsics for armv8-aes-asm_c.c: lines 24853-24884 (AES_GCM_ghash_block_AARCH64)
 *
 * GHASH single-block GF(2^128) multiply-reduce. On real MSVC cl.exe the low-half
 * PMULL intrinsic vmull_p64 takes __n64 (poly64x1_t via vget_low_p64); the high
 * form vmull_high_p64 and vreinterpretq_u8_p128 are used directly. poly128_t is
 * never named (no MSVC spelling). NEON crypto (PMULL) is available
 * unconditionally on MSVC ARM64, so no target-feature pragma is required. */

static WC_INLINE uint8x16_t gf_pmull_low(poly64x2_t a, poly64x2_t b)
{
    return vreinterpretq_u8_p128(vmull_p64(vget_low_p64(a), vget_low_p64(b)));
}

static WC_INLINE uint8x16_t gf_pmull_high(poly64x2_t a, poly64x2_t b)
{
    return vreinterpretq_u8_p128(vmull_high_p64(a, b));
}

void AES_GCM_ghash_block_AARCH64(const byte* data, byte* tag, byte* gcm_h)
{
    uint8x16_t v6 = vld1q_u8(tag);
    uint8x16_t v5 = vld1q_u8(gcm_h);
    uint8x16_t v4 = vrbitq_u8(vld1q_u8(data));
    uint8x16_t v8 = veorq_u8(v6, v4);

    poly64x2_t p8 = vreinterpretq_p64_u8(v8);
    poly64x2_t p5 = vreinterpretq_p64_u8(v5);

    /* X = C * H^1 (Karatsuba: low, high, cross/middle term) */
    uint8x16_t v0 = gf_pmull_low(p8, p5);
    uint8x16_t v1 = gf_pmull_high(p8, p5);
    uint8x16_t v3 = vextq_u8(v8, v8, 8);
    poly64x2_t p3 = vreinterpretq_p64_u8(v3);
    uint8x16_t v2 = gf_pmull_low(p3, p5);
    v2 = veorq_u8(v2, gf_pmull_high(p3, p5));

    /* Reduce modulo the GCM polynomial via the 0x87 constant. */
    poly64x2_t p7 = vreinterpretq_p64_u64(vdupq_n_u64(0x87));
    v3 = vextq_u8(v0, v1, 8);
    v3 = veorq_u8(v3, gf_pmull_high(vreinterpretq_p64_u8(v1), p7));
    v3 = veorq_u8(v3, v2);
    uint8x16_t r2 = gf_pmull_high(vreinterpretq_p64_u8(v3), p7);

    /* mov v0.d[1], v3.d[0] */
    uint64x2_t v0u = vreinterpretq_u64_u8(v0);
    uint64x2_t v3u = vreinterpretq_u64_u8(v3);
    v0u = vsetq_lane_u64(vgetq_lane_u64(v3u, 0), v0u, 1);

    v6 = veorq_u8(vreinterpretq_u8_u64(v0u), r2);
    vst1q_u8(tag, v6);
}

/* intrinsics for armv8-aes-asm_c.c: lines 5203-5254 (AES_GCM_set_key_AARCH64)
 *
 * GHASH hash subkey H = rbit(AES_encrypt(nonce)) — the single-block AES encrypt
 * round chain followed by a byte-wise bit reversal. */
void AES_GCM_set_key_AARCH64(const byte* nonce, const byte* key, byte* gcm_h,
    int nr)
{
    uint8x16_t s = vld1q_u8(nonce);
    int i;
    for (i = 0; i < nr - 1; i++) {
        s = vaeseq_u8(s, vld1q_u8(key + i * 16));
        s = vaesmcq_u8(s);
    }
    s = vaeseq_u8(s, vld1q_u8(key + (nr - 1) * 16));
    s = veorq_u8(s, vld1q_u8(key + nr * 16));
    s = vrbitq_u8(s);
    vst1q_u8(gcm_h, s);
}

/* intrinsics for armv8-aes-asm_c.c: lines 585-634 (AES_encrypt_AARCH64)
 *
 * AES single-block encrypt via ARMv8 AES instructions. `key` points to (nr+1)
 * contiguous 16-byte expanded round keys (the asm's post-incremented loads).
 * nr-1 rounds of aese+aesmc, a final aese (no mix column), then XOR round key nr.
 * nr = 10/12/14 for AES-128/192/256. aese/aesmc take/return uint8x16_t on both
 * MSVC and clang, so no vmull_p64-style compiler split is needed. */
void AES_encrypt_AARCH64(const byte* inBlock, byte* outBlock, byte* key, int nr)
{
    uint8x16_t s = vld1q_u8(inBlock);
    int i;
    for (i = 0; i < nr - 1; i++) {
        s = vaeseq_u8(s, vld1q_u8(key + i * 16));
        s = vaesmcq_u8(s);
    }
    s = vaeseq_u8(s, vld1q_u8(key + (nr - 1) * 16));
    s = veorq_u8(s, vld1q_u8(key + nr * 16));
    vst1q_u8(outBlock, s);
}

/* intrinsics for armv8-aes-asm_c.c: lines 639-688 (AES_decrypt_AARCH64)
 *
 * AES single-block decrypt (aesd/aesimc), mirroring the encrypt kernel with the
 * inverse key schedule. Same round structure and key layout as encrypt. */
void AES_decrypt_AARCH64(const byte* inBlock, byte* outBlock, byte* key, int nr)
{
    uint8x16_t s = vld1q_u8(inBlock);
    int i;
    for (i = 0; i < nr - 1; i++) {
        s = vaesdq_u8(s, vld1q_u8(key + i * 16));
        s = vaesimcq_u8(s);
    }
    s = vaesdq_u8(s, vld1q_u8(key + (nr - 1) * 16));
    s = veorq_u8(s, vld1q_u8(key + nr * 16));
    vst1q_u8(outBlock, s);
}

/* intrinsics for armv8-aes-asm_c.c: lines 3137-3272 (AES_CBC_encrypt_AARCH64)
 *
 * AES-CBC encrypt over sz bytes (sz>>4 blocks). State starts from the IV (reg);
 * each block XORs the plaintext into the chaining value, runs the single-block
 * AES encrypt round chain, and the ciphertext becomes the next block's chaining
 * value. The updated chaining value is written back to reg. CBC is serial — no
 * cross-block vectorization. Round keys are (nr+1) contiguous 16-byte blocks;
 * the asm's three unrolled 128/192/256 paths collapse to one nr-driven loop. */
void AES_CBC_encrypt_AARCH64(const byte* in, byte* out, word32 sz, byte* reg,
    byte* key, int nr)
{
    uint8x16_t state = vld1q_u8(reg);
    word32 blocks = sz >> 4;
    word32 b;
    for (b = 0; b < blocks; b++) {
        int i;
        state = veorq_u8(state, vld1q_u8(in + b * 16));
        for (i = 0; i < nr - 1; i++) {
            state = vaeseq_u8(state, vld1q_u8(key + i * 16));
            state = vaesmcq_u8(state);
        }
        state = vaeseq_u8(state, vld1q_u8(key + (nr - 1) * 16));
        state = veorq_u8(state, vld1q_u8(key + nr * 16));
        vst1q_u8(out + b * 16, state);
    }
    vst1q_u8(reg, state);
}

/* intrinsics for armv8-aes-asm_c.c: lines 3275-3528 (AES_CBC_decrypt_AARCH64)
 *
 * AES-CBC decrypt: plaintext[i] = AES_decrypt(ct[i]) XOR prev_ct (prev_ct is the
 * IV for block 0, else ct[i-1]). Save each ciphertext block before decrypting it
 * (it is the next chaining value); write the final ciphertext block back to reg.
 * The asm's interleaved long/tail paths per key size collapse to one serial loop.
 * `key` here is the decrypt (equivalent-inverse-cipher) schedule that
 * AES_set_key produced for dir=decrypt. */
void AES_CBC_decrypt_AARCH64(const byte* in, byte* out, word32 sz, byte* reg,
    byte* key, int nr)
{
    uint8x16_t prev = vld1q_u8(reg);
    word32 blocks = sz >> 4;
    word32 b;
    for (b = 0; b < blocks; b++) {
        uint8x16_t ct = vld1q_u8(in + b * 16);
        uint8x16_t s = ct;
        int i;
        for (i = 0; i < nr - 1; i++) {
            s = vaesdq_u8(s, vld1q_u8(key + i * 16));
            s = vaesimcq_u8(s);
        }
        s = vaesdq_u8(s, vld1q_u8(key + (nr - 1) * 16));
        s = veorq_u8(s, vld1q_u8(key + nr * 16));
        s = veorq_u8(s, prev);
        vst1q_u8(out + b * 16, s);
        prev = ct;
    }
    vst1q_u8(reg, prev);
}

/* ---- AES-GCM helper kernels (armv8-aes-asm_c.c) ---- */

/* AES-encrypt one 16-byte state with (nr+1) round keys (shared by GCM helpers). */
static WC_INLINE uint8x16_t AES_enc_block_vec(uint8x16_t s, const byte* key, int nr)
{
    int i;
    for (i = 0; i < nr - 1; i++) {
        s = vaeseq_u8(s, vld1q_u8(key + i * 16));
        s = vaesmcq_u8(s);
    }
    s = vaeseq_u8(s, vld1q_u8(key + (nr - 1) * 16));
    return veorq_u8(s, vld1q_u8(key + nr * 16));
}

/* One GHASH GF(2^128) multiply-reduce: returns (tagv * H) reduced. tagv must
 * already include the folded-in data (caller does tagv ^= rbit(block)). */
static WC_INLINE uint8x16_t AES_gcm_ghash_mul(uint8x16_t tagv, uint8x16_t H)
{
    poly64x2_t p8 = vreinterpretq_p64_u8(tagv);
    poly64x2_t p5 = vreinterpretq_p64_u8(H);
    uint8x16_t v0 = gf_pmull_low(p8, p5);
    uint8x16_t v1 = gf_pmull_high(p8, p5);
    uint8x16_t v3 = vextq_u8(tagv, tagv, 8);
    poly64x2_t p3 = vreinterpretq_p64_u8(v3);
    uint8x16_t v2 = veorq_u8(gf_pmull_low(p3, p5), gf_pmull_high(p3, p5));
    poly64x2_t p7 = vreinterpretq_p64_u64(vdupq_n_u64(0x87));
    uint8x16_t r2;
    uint64x2_t v0u;
    v3 = vextq_u8(v0, v1, 8);
    v3 = veorq_u8(v3, gf_pmull_high(vreinterpretq_p64_u8(v1), p7));
    v3 = veorq_u8(v3, v2);
    r2 = gf_pmull_high(vreinterpretq_p64_u8(v3), p7);
    v0u = vreinterpretq_u64_u8(v0);
    v0u = vsetq_lane_u64(vgetq_lane_u64(vreinterpretq_u64_u8(v3), 0), v0u, 1);
    return veorq_u8(vreinterpretq_u8_u64(v0u), r2);
}

/* 64-bit register bit-reverse (matches the asm's `rbit x,x` on lengths). */
static WC_INLINE word64 AES_rbit64(word64 v)
{
    word64 r = 0;
    int i;
    for (i = 0; i < 64; i++) { r = (r << 1) | (v & 1); v >>= 1; }
    return r;
}

/* Shared GHASH length-finalization: fold the (abytes,nbytes) bit-length block,
 * final multiply, rbit, XOR the encrypted J0 (initCtr) => final tag vector. */
static WC_INLINE uint8x16_t AES_gcm_final_tag(const byte* tag, const byte* h,
    const byte* initCtr, word32 nbytes, word32 abytes)
{
    uint8x16_t tagv = vld1q_u8(tag);
    uint8x16_t H = vld1q_u8(h);
    uint64x2_t L = vdupq_n_u64(0);
    L = vsetq_lane_u64(AES_rbit64((word64)abytes << 3), L, 0);
    L = vsetq_lane_u64(AES_rbit64((word64)nbytes << 3), L, 1);
    tagv = veorq_u8(tagv, vreinterpretq_u8_u64(L));
    tagv = AES_gcm_ghash_mul(tagv, H);
    tagv = vrbitq_u8(tagv);
    return veorq_u8(tagv, vld1q_u8(initCtr));
}

/* intrinsics for armv8-aes-asm_c.c: lines 25232-25290 (AES_GCM_encrypt_block_AARCH64)
 * CTR single block: increment big-endian counter word[3], AES-encrypt, XOR input. */
void AES_GCM_encrypt_block_AARCH64(const byte* key, int nr, byte* out,
    const byte* in, byte* counter)
{
    uint8x16_t ctr = vld1q_u8(counter);
    uint32_t w = vgetq_lane_u32(vreinterpretq_u32_u8(ctr), 3);
    uint8x16_t ks;
    w = _byteswap_ulong(_byteswap_ulong(w) + 1);   /* rev, +1, rev */
    ctr = vreinterpretq_u8_u32(vsetq_lane_u32(w, vreinterpretq_u32_u8(ctr), 3));
    vst1q_u8(counter, ctr);
    ks = AES_enc_block_vec(ctr, key, nr);
    vst1q_u8(out, veorq_u8(vld1q_u8(in), ks));
}

/* intrinsics for armv8-aes-asm_c.c: lines 24886-25231 (AES_GCM_aad_update_AARCH64)
 * GHASH-fold full AAD blocks into the running tag (per-block form). */
void AES_GCM_aad_update_AARCH64(const byte* aadt, word32 abytes, byte* tag,
    byte* gcm_h)
{
    uint8x16_t t = vld1q_u8(tag);
    uint8x16_t H = vld1q_u8(gcm_h);
    word32 blocks = abytes >> 4;
    word32 b;
    for (b = 0; b < blocks; b++) {
        uint8x16_t d = vrbitq_u8(vld1q_u8(aadt + b * 16));
        t = AES_gcm_ghash_mul(veorq_u8(t, d), H);
    }
    vst1q_u8(tag, t);
}

/* intrinsics for armv8-aes-asm_c.c: lines 24675-24851 (AES_GCM_init_AARCH64)
 * Derive J0 from the nonce (12-byte fast path or GHASH-nonce path), store as the
 * working counter, and AES-encrypt J0 into initCtr. */
void AES_GCM_init_AARCH64(byte* key, int nr, const byte* nonce, word32 nonceSz,
    byte* gcm_h, byte* counter, byte* initCtr)
{
    uint8x16_t J0;
    if (nonceSz == 12) {
        byte b[16];
        memcpy(b, nonce, 12);
        b[12] = 0; b[13] = 0; b[14] = 0; b[15] = 1;
        J0 = vld1q_u8(b);
    }
    else {
        uint8x16_t H = vld1q_u8(gcm_h);
        uint8x16_t t = vdupq_n_u8(0);
        word32 blocks = nonceSz >> 4;
        word32 rem = nonceSz & 15;
        word64 len;
        uint64x2_t L;
        uint8x16_t Lv;
        word32 i;
        for (i = 0; i < blocks; i++) {
            uint8x16_t d = vrbitq_u8(vld1q_u8(nonce + i * 16));
            t = AES_gcm_ghash_mul(veorq_u8(t, d), H);
        }
        if (rem) {
            byte b[16];
            uint8x16_t d;
            memset(b, 0, 16);
            memcpy(b, nonce + blocks * 16, rem);
            d = vrbitq_u8(vld1q_u8(b));
            t = AES_gcm_ghash_mul(veorq_u8(t, d), H);
        }
        len = (word64)nonceSz << 3;
        L = vdupq_n_u64(0);
        L = vsetq_lane_u64(_byteswap_uint64(len), L, 1);  /* rev64 lane */
        Lv = vrbitq_u8(vreinterpretq_u8_u64(L));
        t = AES_gcm_ghash_mul(veorq_u8(t, Lv), H);
        J0 = vrbitq_u8(t);
    }
    vst1q_u8(counter, J0);
    vst1q_u8(initCtr, AES_enc_block_vec(J0, key, nr));
}

/* intrinsics for armv8-aes-asm_c.c: lines 29122-29198 (AES_GCM_encrypt_final_AARCH64)
 * GHASH length-finalize the tag, then output tbytes of it. */
void AES_GCM_encrypt_final_AARCH64(byte* tag, byte* authTag, word32 tbytes,
    word32 nbytes, word32 abytes, byte* h, byte* initCtr)
{
    uint8x16_t t = AES_gcm_final_tag(tag, h, initCtr, nbytes, abytes);
    byte buf[16];
    vst1q_u8(buf, t);
    memcpy(authTag, buf, tbytes == 16 ? 16 : tbytes);
}

/* intrinsics for armv8-aes-asm_c.c: lines 33031-33138 (AES_GCM_decrypt_final_AARCH64)
 * GHASH length-finalize, then constant-time compare vs authTag over tbytes.
 * Result encoding matches the asm: match => 180 (0xb4), mismatch => 0. */
void AES_GCM_decrypt_final_AARCH64(byte* tag, const byte* authTag, word32 tbytes,
    word32 nbytes, word32 abytes, byte* h, byte* initCtr, int* res)
{
    uint8x16_t t = AES_gcm_final_tag(tag, h, initCtr, nbytes, abytes);
    byte computed[16];
    byte provided[16];
    word32 n = (tbytes > 16) ? 16 : tbytes;
    byte diff = 0;
    word32 i;
    vst1q_u8(computed, t);
    memset(provided, 0, 16);
    memcpy(provided, authTag, n);
    if (tbytes < 16) {
        for (i = tbytes; i < 16; i++) computed[i] = 0;
    }
    for (i = 0; i < 16; i++) diff |= (byte)(computed[i] ^ provided[i]);
    *res = (diff == 0) ? 180 : 0;
}

/* ---- AES/AES-GCM DATA-PATH kernels (armv8-aes-asm_c.c) ----
 *
 * The originals are heavily unrolled/pipelined (up to 8 blocks in flight, with a
 * precomputed H^2..H^8 GHASH ladder). These re-express the SEMANTICS as clear
 * loops over the already-verified primitives (single-block AES, single-block
 * GHASH multiply-reduce): semantics preserved, not the asm's unrolling. Each was
 * proven byte-identical to the original inline asm in VerificationDataPath/
 * (10 gtests incl. FIPS-197, SP800-38A CTR and NIST GCM KATs), with three
 * negative controls proven RED. */

/* GHASH-fold one 16-byte block (bit-reversed, as wolfSSL stores GHASH state). */
static WC_INLINE uint8x16_t AES_gcm_ghash_fold(uint8x16_t tagv, const byte* blk,
    uint8x16_t H)
{
    return AES_gcm_ghash_mul(veorq_u8(tagv, vrbitq_u8(vld1q_u8(blk))), H);
}

/* GHASH-fold a zero-padded partial block. */
static WC_INLINE uint8x16_t AES_gcm_ghash_fold_partial(uint8x16_t tagv,
    const byte* p, word32 n, uint8x16_t H)
{
    byte b[16];
    memset(b, 0, 16);
    memcpy(b, p, n);
    return AES_gcm_ghash_fold(tagv, b, H);
}

/* AES single-block decrypt with (nr+1) contiguous round keys. */
static WC_INLINE uint8x16_t AES_dec_block_vec(uint8x16_t s, const byte* key,
    int nr)
{
    int i;
    for (i = 0; i < nr - 1; i++) {
        s = vaesdq_u8(s, vld1q_u8(key + i * 16));
        s = vaesimcq_u8(s);
    }
    s = vaesdq_u8(s, vld1q_u8(key + (nr - 1) * 16));
    return veorq_u8(s, vld1q_u8(key + nr * 16));
}

/* GCM CTR step: increment the counter's LOW 32 BITS (word[3], big-endian). */
static WC_INLINE uint8x16_t AES_gcm_ctr_next(uint8x16_t* ctr)
{
    uint32x4_t c = vreinterpretq_u32_u8(*ctr);
    word32 w = _byteswap_ulong(_byteswap_ulong(vgetq_lane_u32(c, 3)) + 1);
    *ctr = vreinterpretq_u8_u32(vsetq_lane_u32(w, c, 3));
    return *ctr;
}

/* intrinsics for armv8-aes-asm_c.c: lines 693-1911 (AES_encrypt_blocks_AARCH64)
 * AES-ECB encrypt: every block independent, no chaining. */
void AES_encrypt_blocks_AARCH64(const byte* in, byte* out, word32 sz, byte* key,
    int nr)
{
    word32 blocks = sz >> 4;
    word32 b;
    for (b = 0; b < blocks; b++)
        vst1q_u8(out + b * 16, AES_enc_block_vec(vld1q_u8(in + b * 16), key, nr));
}

/* intrinsics for armv8-aes-asm_c.c: lines 1914-3132 (AES_decrypt_blocks_AARCH64)
 * AES-ECB decrypt with the equivalent-inverse-cipher schedule. */
void AES_decrypt_blocks_AARCH64(const byte* in, byte* out, word32 sz, byte* key,
    int nr)
{
    word32 blocks = sz >> 4;
    word32 b;
    for (b = 0; b < blocks; b++)
        vst1q_u8(out + b * 16, AES_dec_block_vec(vld1q_u8(in + b * 16), key, nr));
}

/* intrinsics for armv8-aes-asm_c.c: lines 3533-5199 (AES_CTR_encrypt_AARCH64)
 *
 * AES-CTR. The counter in `reg` is a FULL 128-bit BIG-ENDIAN value; the asm keeps
 * it as two host-endian 64-bit halves (rev64) and does adds/adc for a true
 * 128-bit +1 — NOT the 32-bit word[3] increment GCM uses. The counter is used
 * AS-IS for block 0 (post-increment), whereas GCM pre-increments.
 *
 * A partial tail stores the WHOLE keystream block to tmp and writes
 * *left = 16 - partial. *left is never READ here: aes.c drains leftover
 * keystream bytes before calling and passes the already-advanced in/out/sz. When
 * sz is a whole multiple of 16, tmp and *left are left untouched. */
void AES_CTR_encrypt_AARCH64(const byte* in, byte* out, word32 sz, byte* reg,
    byte* key, byte* tmp, word32* left, word32 nr)
{
    word32 blocks = sz >> 4;
    word32 partial = sz & 15;
    word64 hi, lo, bhi, blo;
    word32 b, i;
    byte cb[16];

    memcpy(&hi, reg + 0, 8);
    memcpy(&lo, reg + 8, 8);
    hi = _byteswap_uint64(hi);
    lo = _byteswap_uint64(lo);

    for (b = 0; b < blocks; b++) {
        bhi = _byteswap_uint64(hi); blo = _byteswap_uint64(lo);
        memcpy(cb, &bhi, 8); memcpy(cb + 8, &blo, 8);
        vst1q_u8(out + b * 16, veorq_u8(vld1q_u8(in + b * 16),
            AES_enc_block_vec(vld1q_u8(cb), key, (int)nr)));
        if (++lo == 0) ++hi;    /* adds/adc: 128-bit increment */
    }
    if (partial) {
        const byte* pin = in + blocks * 16;
        byte* pout = out + blocks * 16;
        bhi = _byteswap_uint64(hi); blo = _byteswap_uint64(lo);
        memcpy(cb, &bhi, 8); memcpy(cb + 8, &blo, 8);
        vst1q_u8(tmp, AES_enc_block_vec(vld1q_u8(cb), key, (int)nr));
        if (++lo == 0) ++hi;
        for (i = 0; i < partial; i++) pout[i] = (byte)(tmp[i] ^ pin[i]);
        *left = 16 - partial;
    }
    bhi = _byteswap_uint64(hi); blo = _byteswap_uint64(lo);
    memcpy(reg + 0, &bhi, 8); memcpy(reg + 8, &blo, 8);
}

/* Shared J0 derivation for the one-shot GCM kernels (12-byte nonce fast path,
 * else GHASH the nonce plus its length block). Mirrors AES_GCM_init_AARCH64. */
static WC_INLINE uint8x16_t AES_gcm_j0(const byte* nonce, word32 nonceSz,
    uint8x16_t H)
{
    uint8x16_t t;
    word32 blocks, rem, i;
    uint64x2_t L;

    if (nonceSz == 12) {
        byte b[16];
        memcpy(b, nonce, 12);
        b[12] = 0; b[13] = 0; b[14] = 0; b[15] = 1;
        return vld1q_u8(b);
    }
    t = vdupq_n_u8(0);
    blocks = nonceSz >> 4;
    rem = nonceSz & 15;
    for (i = 0; i < blocks; i++) t = AES_gcm_ghash_fold(t, nonce + i * 16, H);
    if (rem) t = AES_gcm_ghash_fold_partial(t, nonce + blocks * 16, rem, H);
    L = vdupq_n_u64(0);
    L = vsetq_lane_u64(_byteswap_uint64((word64)nonceSz << 3), L, 1);
    t = AES_gcm_ghash_mul(veorq_u8(t, vrbitq_u8(vreinterpretq_u8_u64(L))), H);
    return vrbitq_u8(t);
}

/* Shared GCM tag finalize over the (aadSz,sz) bit-length block. */
static WC_INLINE uint8x16_t AES_gcm_tag_finish(uint8x16_t tagv, uint8x16_t H,
    uint8x16_t encJ0, word32 sz, word32 aadSz)
{
    uint64x2_t L = vdupq_n_u64(0);
    L = vsetq_lane_u64(AES_rbit64((word64)aadSz << 3), L, 0);
    L = vsetq_lane_u64(AES_rbit64((word64)sz << 3), L, 1);
    tagv = AES_gcm_ghash_mul(veorq_u8(tagv, vreinterpretq_u8_u64(L)), H);
    return veorq_u8(vrbitq_u8(tagv), encJ0);
}

/* intrinsics for armv8-aes-asm_c.c: lines 5256-10136 (AES_GCM_encrypt_AARCH64)
 * One-shot GCM encrypt: J0, GHASH the AAD, CTR-encrypt while GHASHing the
 * ciphertext, then finalize the tag over the length block. */
void AES_GCM_encrypt_AARCH64(const byte* in, byte* out, word32 sz,
    const byte* nonce, word32 nonceSz, byte* tag, word32 tagSz, const byte* aad,
    word32 aadSz, byte* key, byte* gcm_h, byte* tmp, byte* reg, int nr)
{
    uint8x16_t H = vld1q_u8(gcm_h);
    uint8x16_t J0 = AES_gcm_j0(nonce, nonceSz, H);
    uint8x16_t encJ0 = AES_enc_block_vec(J0, key, nr);
    uint8x16_t t = vdupq_n_u8(0);
    uint8x16_t ctr = J0;
    word32 ab = aadSz >> 4, ar = aadSz & 15;
    word32 blocks = sz >> 4, rem = sz & 15;
    word32 i, b;
    byte fb[16];

    (void)tmp;
    vst1q_u8(reg, J0);
    for (i = 0; i < ab; i++) t = AES_gcm_ghash_fold(t, aad + i * 16, H);
    if (ar) t = AES_gcm_ghash_fold_partial(t, aad + ab * 16, ar, H);

    for (b = 0; b < blocks; b++) {
        uint8x16_t ct = veorq_u8(vld1q_u8(in + b * 16),
            AES_enc_block_vec(AES_gcm_ctr_next(&ctr), key, nr));
        vst1q_u8(out + b * 16, ct);
        t = AES_gcm_ghash_mul(veorq_u8(t, vrbitq_u8(ct)), H);
    }
    if (rem) {
        byte kb[16], cb[16];
        vst1q_u8(kb, AES_enc_block_vec(AES_gcm_ctr_next(&ctr), key, nr));
        memset(cb, 0, 16);
        for (i = 0; i < rem; i++) {
            cb[i] = (byte)(in[blocks * 16 + i] ^ kb[i]);
            out[blocks * 16 + i] = cb[i];
        }
        t = AES_gcm_ghash_fold(t, cb, H);
    }
    vst1q_u8(fb, AES_gcm_tag_finish(t, H, encJ0, sz, aadSz));
    memcpy(tag, fb, tagSz > 16 ? 16 : tagSz);
}

/* intrinsics for armv8-aes-asm_c.c: lines 10139-15070 (AES_GCM_decrypt_AARCH64)
 * One-shot GCM decrypt: GHASHes the ciphertext (input) while CTR-decrypting, then
 * verifies the tag. RETURN ENCODING: 0 on match, -180 (AES_GCM_AUTH_E) on
 * mismatch — the asm does `csetm ne; and #-180` and aes.c assigns the return
 * value straight to `ret`. (Distinct from AES_GCM_decrypt_final_AARCH64, whose
 * *res is 180 on match / 0 on mismatch.) */
int AES_GCM_decrypt_AARCH64(const byte* in, byte* out, word32 sz,
    const byte* nonce, word32 nonceSz, const byte* tag, word32 tagSz,
    const byte* aad, word32 aadSz, byte* key, byte* gcm_h, byte* tmp, byte* reg,
    int nr)
{
    uint8x16_t H = vld1q_u8(gcm_h);
    uint8x16_t J0 = AES_gcm_j0(nonce, nonceSz, H);
    uint8x16_t encJ0 = AES_enc_block_vec(J0, key, nr);
    uint8x16_t t = vdupq_n_u8(0);
    uint8x16_t ctr = J0;
    word32 ab = aadSz >> 4, ar = aadSz & 15;
    word32 blocks = sz >> 4, rem = sz & 15;
    word32 i, b, n;
    byte fb[16];
    byte diff = 0;

    (void)tmp;
    vst1q_u8(reg, J0);
    for (i = 0; i < ab; i++) t = AES_gcm_ghash_fold(t, aad + i * 16, H);
    if (ar) t = AES_gcm_ghash_fold_partial(t, aad + ab * 16, ar, H);

    for (b = 0; b < blocks; b++) {
        uint8x16_t ct = vld1q_u8(in + b * 16);
        t = AES_gcm_ghash_mul(veorq_u8(t, vrbitq_u8(ct)), H);
        vst1q_u8(out + b * 16, veorq_u8(ct,
            AES_enc_block_vec(AES_gcm_ctr_next(&ctr), key, nr)));
    }
    if (rem) {
        byte kb[16];
        t = AES_gcm_ghash_fold_partial(t, in + blocks * 16, rem, H);
        vst1q_u8(kb, AES_enc_block_vec(AES_gcm_ctr_next(&ctr), key, nr));
        for (i = 0; i < rem; i++)
            out[blocks * 16 + i] = (byte)(in[blocks * 16 + i] ^ kb[i]);
    }
    vst1q_u8(fb, AES_gcm_tag_finish(t, H, encJ0, sz, aadSz));

    n = tagSz > 16 ? 16 : tagSz;
    for (i = 0; i < n; i++) diff |= (byte)(fb[i] ^ tag[i]);
    return (diff == 0) ? 0 : -180;
}

/* intrinsics for armv8-aes-asm_c.c: lines 25292-29120
 *                                   (AES_GCM_encrypt_update_AARCH64)
 * Streaming GCM encrypt: CTR-encrypt from the running counter while GHASHing the
 * produced ciphertext into the running tag; counter and tag updated in place.
 *
 * WHOLE BLOCKS ONLY: the asm computes blocks = nbytes>>4 and has NO partial-block
 * path. aes.c always passes blocks*WC_AES_BLOCK_SIZE and handles any partial
 * itself (AES_GCM_encrypt_block + AES_GCM_ghash_block on a zero-padded
 * LASTGBLOCK). Do not add a partial path here. */
void AES_GCM_encrypt_update_AARCH64(const byte* key, int nr, byte* out,
    const byte* in, word32 nbytes, byte* tag, byte* h, byte* counter)
{
    uint8x16_t H = vld1q_u8(h);
    uint8x16_t t = vld1q_u8(tag);
    uint8x16_t ctr = vld1q_u8(counter);
    word32 blocks = nbytes >> 4;
    word32 b;
    for (b = 0; b < blocks; b++) {
        uint8x16_t ct = veorq_u8(vld1q_u8(in + b * 16),
            AES_enc_block_vec(AES_gcm_ctr_next(&ctr), key, nr));
        vst1q_u8(out + b * 16, ct);
        t = AES_gcm_ghash_mul(veorq_u8(t, vrbitq_u8(ct)), H);
    }
    vst1q_u8(tag, t);
    vst1q_u8(counter, ctr);
}

/* intrinsics for armv8-aes-asm_c.c: lines 29200-33029
 *                                   (AES_GCM_decrypt_update_AARCH64)
 * Streaming GCM decrypt; whole blocks only, same contract as the encrypt side. */
void AES_GCM_decrypt_update_AARCH64(const byte* key, int nr, byte* out,
    const byte* in, word32 nbytes, byte* tag, byte* h, byte* counter)
{
    uint8x16_t H = vld1q_u8(h);
    uint8x16_t t = vld1q_u8(tag);
    uint8x16_t ctr = vld1q_u8(counter);
    word32 blocks = nbytes >> 4;
    word32 b;
    for (b = 0; b < blocks; b++) {
        uint8x16_t ct = vld1q_u8(in + b * 16);
        t = AES_gcm_ghash_mul(veorq_u8(t, vrbitq_u8(ct)), H);
        vst1q_u8(out + b * 16, veorq_u8(ct,
            AES_enc_block_vec(AES_gcm_ctr_next(&ctr), key, nr)));
    }
    vst1q_u8(tag, t);
    vst1q_u8(counter, ctr);
}

/* ---- Base software-fallback layer ----
 *
 * Besides the hardware-crypto *_AARCH64 kernels above, aes.c UNCONDITIONALLY
 * references a second, table-based software layer (AES_ECB/CBC/CTR/GCM_encrypt,
 * GCM_gmult_len). Upstream those live in armv8-aes-asm_c.c as GCC inline asm
 * (T-table AES + a table-driven GHASH), so MSVC cannot build them.
 *
 * At runtime this layer is DEAD CODE in this build: Check_CPU_support_HwCrypto
 * sets use_aes_hw_crypto/use_pmull_hw_crypto unconditionally (see
 * WOLFSSL_ARMASM_FORCE_HW_CRYPTO), so every call site takes the hw-crypto
 * branch. Only the linker needs the symbols. Rather than transliterate a second
 * asm implementation that never executes, these are thin wrappers over the
 * already-verified kernels above — semantically equivalent (identical mode
 * definitions and counter conventions, confirmed against the upstream asm:
 * base AES_CTR_encrypt increments a full 128-bit big-endian counter via
 * adds/adc, while base AES_GCM_encrypt increments only the big-endian word[3]
 * via rev32 + add w9 — matching AES_CTR_encrypt_AARCH64 and the GCM kernels
 * respectively), so behavior is correct even if a future change did reach them.
 *
 * `len` is a byte count and callers only pass whole blocks here; `ks` is the
 * expanded key schedule; the T-table operand of the upstream asm is not needed
 * because the AES instructions compute the S-box directly. */

void AES_ECB_encrypt(const unsigned char* in, unsigned char* out,
    unsigned long len, const unsigned char* ks, int nr)
{
    AES_encrypt_blocks_AARCH64(in, out, (word32)len, (byte*)ks, nr);
}

void AES_ECB_decrypt(const unsigned char* in, unsigned char* out,
    unsigned long len, const unsigned char* ks, int nr)
{
    AES_decrypt_blocks_AARCH64(in, out, (word32)len, (byte*)ks, nr);
}

void AES_CBC_encrypt(const unsigned char* in, unsigned char* out,
    unsigned long len, const unsigned char* ks, int nr, unsigned char* iv)
{
    AES_CBC_encrypt_AARCH64(in, out, (word32)len, iv, (byte*)ks, nr);
}

void AES_CBC_decrypt(const unsigned char* in, unsigned char* out,
    unsigned long len, const unsigned char* ks, int nr, unsigned char* iv)
{
    AES_CBC_decrypt_AARCH64(in, out, (word32)len, iv, (byte*)ks, nr);
}

/* Full 128-bit big-endian counter (as the upstream base kernel does). The
 * *_AARCH64 CTR kernel also maintains a leftover-keystream block, which this
 * entry point has no parameters for; callers here always pass whole blocks, so
 * pass local scratch and discard it. */
void AES_CTR_encrypt(const unsigned char* in, unsigned char* out,
    unsigned long len, const unsigned char* ks, int nr, unsigned char* ctr)
{
    byte tmp[16];
    word32 left = 0;
    AES_CTR_encrypt_AARCH64(in, out, (word32)len, ctr, (byte*)ks, tmp, &left,
        (word32)nr);
}

/* GCM keystream only (no GHASH: aes.c folds the tag via GCM_GMULT_LEN itself).
 * Counter is the big-endian word[3] form. */
void AES_GCM_encrypt(const unsigned char* in, unsigned char* out,
    unsigned long len, const unsigned char* ks, int nr, unsigned char* ctr)
{
    uint8x16_t c = vld1q_u8(ctr);
    word32 blocks = (word32)(len >> 4);
    word32 b;
    for (b = 0; b < blocks; b++) {
        vst1q_u8(out + b * 16, veorq_u8(vld1q_u8(in + b * 16),
            AES_enc_block_vec(AES_gcm_ctr_next(&c), (const byte*)ks, nr)));
    }
    vst1q_u8(ctr, c);
}

/* GHASH-fold `len` bytes into the running state x.
 *
 * Upstream this is a 4-bit-table routine driven by Gcm::M0. Rather than
 * re-derive that table algorithm (32 pre-rotated entries plus a remainder
 * table - easy to get subtly wrong, and it would never execute here), recover
 * the hash subkey and reuse the PMULL GHASH kernel that is already proven
 * byte-exact against the upstream asm.
 *
 * GenerateM0() builds the table from the subkey with `m[0x8] = gcm->H`
 * (XMEMCPY, no transform), and the byte-reversing fixup at the end of
 * GenerateM0 is gated on WOLFSSL_ARMASM_NO_HW_CRYPTO, which this build does not
 * define. So M0[8] is exactly gcm->H, in the same bit-reversed representation
 * that AES_GCM_set_key_AARCH64 produced and that AES_GCM_ghash_block_AARCH64
 * consumes. */
void GCM_gmult_len(unsigned char* x, const unsigned char** m,
    const unsigned char* data, unsigned long len)
{
    const byte (*M0)[16] = (const byte (*)[16])m;
    byte h[16];

    memcpy(h, M0[0x8], 16);
    while (len >= 16) {
        AES_GCM_ghash_block_AARCH64(data, x, h);
        data += 16;
        len -= 16;
    }
}

#endif /* WOLFSSL_ARMASM && real-MSVC ARM64 && HW crypto */
