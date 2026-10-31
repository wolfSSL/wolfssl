/* rng_noisesrc.c
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

#ifdef WOLFSSL_NOISE_SRC

#include <wolfssl/wolfcrypt/rng_noisesrc.h>

#ifndef WOLFSSL_SHA3
    #error "rng_noisesrc.c conditions with SHA3-256: define WOLFSSL_SHA3"
#endif

#ifdef HAVE_FIPS
    /* for fips @wc_fips: this file sits outside the module boundary, and the
     * fips.h redirect is what makes its SHA3 calls approved service calls. */
    #include <wolfssl/wolfcrypt/fips.h>
#endif

#include <wolfssl/wolfcrypt/sha3.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/* Generic SP800-90B noise source.  Configuration struct and API:
 * wolfssl/wolfcrypt/rng_noisesrc.h.
 *
 * Entropy model.  A port supplies raw, unconditioned octets through one
 * callback.  Each raw bit is credited hmin/100 bits of min-entropy, so a
 * full-entropy output octet needs 8 / (hmin/100) raw bits, and margin
 * oversamples on top of that; WC_NOISE_RAW_PER_SRC() turns the two into the
 * raw octets gathered per conditioner chunk.  Only source 0 is budgeted - any
 * further source is hashed in as defence in depth, and extra hash input can
 * never subtract entropy.
 *
 * Every gathered octet passes the 4.4.1 Repetition Count Test and the 4.4.2
 * Adaptive Proportion Test (sliding window, as in wolfEntropy) before
 * reaching the conditioner, and _Init() runs the 4.3 startup test over
 * startupOctets per source first.
 *
 * Failure is reset-and-retry, as for wolfEntropy.  A test verdict on any
 * source - a health test or a _SelfTest() liveness check - fails the call with
 * no output and resets that source's test state, so the next call reruns its
 * 4.3 startup test before anything is released again.  A source that stays
 * broken therefore fails every call.  An error from the sample callback
 * propagates as returned and is retryable: it says the hardware did not
 * answer, not that the noise is bad.
 *
 * Cutoffs belong to the caller and must match the assumed hmin, or they either
 * never trip or trip constantly.  For H bits of min-entropy per octet at
 * alpha = 2^-30: RCT C = 1 + ceil(30/H), APT C = 1 + CRITBINOM(W, 2^-H,
 * 1-alpha).  Zero selects the values for H = 1 and W = 512:
 * RCT C = 1 + 30 = 31, APT C = 1 + CRITBINOM(512, 0.5, 1-2^-30) = 325.
 *
 * No locking.  The instance is caller-owned state, so a port sharing one
 * across threads provides its own mutual exclusion. */

#if WC_NOISE_CHUNK_SZ != WC_SHA3_256_DIGEST_SIZE
    #error "WC_NOISE_CHUNK_SZ must match WC_SHA3_256_DIGEST_SIZE"
#endif

/* Clear both continuous tests.  A cleared state is what makes the next call
 * rerun the startup test. */
static void NoiseSrc_HealthReset(wc_NoiseHealth* st)
{
    ForceZero(st, sizeof(*st));
}

/* Whether a startup test must pass before samples are released: true until
 * one has, and again after any failure reset the state. */
static int NoiseSrc_HealthNeeded(const wc_NoiseHealth* st)
{
    return (st->aptTotal == 0) || (!st->rctHavePrev);
}

/* SP800-90B 4.4.1 Repetition Count Test on one sample. */
static int NoiseSrc_Rct(const wc_NoiseSrc* src, wc_NoiseHealth* st, byte v)
{
    if (st->rctHavePrev && (v == st->rctPrev)) {
        st->rctCnt++;
        if (st->rctCnt >= src->rctCutoff) {
            return ENTROPY_RT_E;
        }
    }
    else {
        st->rctPrev = v;
        st->rctHavePrev = 1;
        st->rctCnt = 1;
    }
    return 0;
}

/* SP800-90B 4.4.2 Adaptive Proportion Test on one sample, over a sliding
 * window: once aptCutoff - 1 samples are queued, every sample is scored
 * against the count of its value in the last aptWindow - 1 samples. */
static int NoiseSrc_Apt(const wc_NoiseSrc* src, wc_NoiseHealth* st, byte v)
{
    st->aptSamples[st->aptLast] = v;
    st->aptLast = (word16)((st->aptLast + 1) % src->aptWindow);
    st->aptCnt[v]++;
    st->aptTotal++;

    if (st->aptTotal >= src->aptCutoff && st->aptCnt[v] >= src->aptCutoff) {
        return ENTROPY_APT_E;
    }
    if (st->aptTotal == src->aptWindow) {
        /* Drop the oldest sample, back to aptWindow - 1 queued. */
        st->aptCnt[st->aptSamples[st->aptFirst]]--;
        st->aptFirst = (word16)((st->aptFirst + 1) % src->aptWindow);
        st->aptTotal--;
    }
    return 0;
}

/* Run each sample through the repetition then proportion test.  Stops at the
 * first failing sample so the rest of the buffer cannot scrub the state that
 * detected it. */
static int NoiseSrc_HealthRun(const wc_NoiseSrc* src, wc_NoiseHealth* st,
    const byte* buf, word32 len)
{
    int ret = 0;
    word32 i;

    for (i = 0; (ret == 0) && (i < len); i++) {
        byte v = (byte)WC_OCTET(buf[i]);

        ret = NoiseSrc_Rct(src, st, v);
        if (ret == 0) {
            ret = NoiseSrc_Apt(src, st, v);
        }
    }

    return ret;
}

/* len raw octets from one source.  No health testing - callers that keep the
 * data run NoiseSrc_HealthRun() over it. */
static int NoiseSrc_Gather(wc_NoiseSrc* src, byte* out, word32 len, int srcIdx)
{
    word32 i;
    int ret;

    for (i = 0; i < len; i++) {
        ret = src->sampleCb(src->ctx, srcIdx, &out[i]);
        if (ret != 0) {
            return ret;
        }
        /* The contract is raw octets, but where CHAR_BIT != 8 a callback can
         * legally leave bits above 0xFF in the cell.  Mask here so the
         * conditioner sees exactly what the health tests scored - they mask
         * already - and no high bits leak into the hash. */
        out[i] = WC_OCTET(out[i]);
    }

    return 0;
}

/* SP800-90B 4.3 startup test for one source: startupOctets through the
 * continuous tests, streamed through the work buffer.  The tests are
 * per-sample state machines, so slicing the stream does not change the
 * verdict.  Any failure leaves the source's state reset so the next call
 * starts over. */
static int NoiseSrc_Startup(wc_NoiseSrc* src, int srcIdx)
{
    wc_NoiseHealth* st = &src->health[srcIdx];
    word32 done;
    word32 take;
    int ret = 0;

    NoiseSrc_HealthReset(st);
    for (done = 0; (ret == 0) && (done < src->startupOctets); done += take) {
        take = src->startupOctets - done;
        if (take > src->workSz) {
            take = src->workSz;
        }
        ret = NoiseSrc_Gather(src, src->work, take, srcIdx);
        if (ret == 0) {
            ret = NoiseSrc_HealthRun(src, st, src->work, take);
        }
    }
    if (ret != 0) {
        NoiseSrc_HealthReset(st);
    }

    ForceZero(src->work, src->workSz);
    return ret;
}

int wc_NoiseSrc_Init(wc_NoiseSrc* src)
{
    int i;
    int ret = 0;

    if (src == NULL) {
        return BAD_FUNC_ARG;
    }

    if (!src->inited) {
        if (src->sampleCb == NULL || src->tag == NULL || src->work == NULL) {
            return BAD_FUNC_ARG;
        }
        if (src->numSrc < 1 || src->numSrc > WC_NOISE_SRC_MAX) {
            return BAD_FUNC_ARG;
        }

        if (src->hmin == 0) {
            src->hmin = WC_NOISE_HMIN_DEF;
        }
        if (src->margin == 0) {
            src->margin = WC_NOISE_MARGIN_DEF;
        }
        if (src->rctCutoff == 0) {
            src->rctCutoff = WC_NOISE_RCT_CUTOFF_DEF;
        }
        if (src->aptWindow == 0) {
            src->aptWindow = WC_NOISE_APT_WINDOW_DEF;
        }
        if (src->aptCutoff == 0) {
            src->aptCutoff = WC_NOISE_APT_CUTOFF_DEF;
        }
        if (src->startupOctets == 0) {
            src->startupOctets = WC_NOISE_STARTUP_DEF;
        }

        if (src->hmin > 100) {
            return BAD_FUNC_ARG;
        }
        if (src->rctCutoff < 2 || src->aptCutoff < 2 || src->aptWindow < 2) {
            return BAD_FUNC_ARG;
        }
        /* The APT queue in wc_NoiseHealth holds one default window. */
        if (src->aptWindow > WC_NOISE_APT_WINDOW_DEF ||
                src->aptCutoff > src->aptWindow) {
            return BAD_FUNC_ARG;
        }
        /* Below one APT window the startup pass never exercises that test. */
        if (src->startupOctets < (word32)src->aptWindow) {
            return BAD_FUNC_ARG;
        }

        src->rawPerSrc = WC_NOISE_RAW_PER_SRC(src->hmin, src->margin);
        if (src->rawPerSrc == 0 ||
                src->workSz < src->rawPerSrc * (word32)src->numSrc) {
            return BUFFER_E;
        }

        XMEMSET(src->health, 0, sizeof(src->health));
        src->chunkCtr = 0;
        /* Set before the startup pass: a failed startup is then retried by
         * the next call without revalidating. */
        src->inited = 1;
    }

    /* SP800-90B 4.3: before releasing anything, every source not already
     * passing pushes startupOctets - more than one APT window - through the
     * continuous tests. */
    for (i = 0; (ret == 0) && (i < (int)src->numSrc); i++) {
        if (NoiseSrc_HealthNeeded(&src->health[i])) {
            ret = NoiseSrc_Startup(src, i);
        }
    }

    return ret;
}

void wc_NoiseSrc_Free(wc_NoiseSrc* src)
{
    if (src == NULL) {
        return;
    }

    if (src->work != NULL && src->workSz > 0) {
        ForceZero(src->work, src->workSz);
    }
    /* The APT queue holds recent raw samples. */
    ForceZero(src->health, sizeof(src->health));
    src->chunkCtr = 0;
    src->inited   = 0;
}

int wc_NoiseSrc_GetRaw(wc_NoiseSrc* src, byte* output, word32 len, int srcIdx)
{
    int ret;

    if (src == NULL || output == NULL) {
        return BAD_FUNC_ARG;
    }
    /* Before _Init(): numSrc is caller configuration, so a bad index need not
     * pay for the startup test or burn hardware entropy first. */
    if (srcIdx < 0 || srcIdx >= (int)src->numSrc) {
        return BAD_FUNC_ARG;
    }

    ret = wc_NoiseSrc_Init(src);
    if (ret != 0) {
        return ret;
    }

    ret = NoiseSrc_Gather(src, output, len, srcIdx);
    if (ret != 0) {
        ForceZero(output, len);
    }
    return ret;
}

/* SHA3-256 over tag || BE32 chunkCtr || each source's raw octets in index
 * order, into digest. */
static int NoiseSrc_Condition(wc_NoiseSrc* src, wc_Sha3* sha, byte* digest)
{
    byte ctrBuf[4];
    int i;
    int ret;

    ret = wc_InitSha3_256(sha, NULL, INVALID_DEVID);
    if (ret != 0) {
        ForceZero(sha, sizeof(*sha));
        return ret;
    }

    ctrBuf[0] = WC_OCTET(src->chunkCtr >> 24);
    ctrBuf[1] = WC_OCTET(src->chunkCtr >> 16);
    ctrBuf[2] = WC_OCTET(src->chunkCtr >> 8);
    ctrBuf[3] = WC_OCTET(src->chunkCtr);

    ret = wc_Sha3_256_Update(sha, (const byte*)src->tag,
                             (word32)XSTRLEN(src->tag));
    if (ret == 0) {
        ret = wc_Sha3_256_Update(sha, ctrBuf, (word32)sizeof(ctrBuf));
    }
    for (i = 0; (ret == 0) && (i < (int)src->numSrc); i++) {
        ret = wc_Sha3_256_Update(sha,
                                 src->work + ((word32)i * src->rawPerSrc),
                                 src->rawPerSrc);
    }
    if (ret == 0) {
        ret = wc_Sha3_256_Final(sha, digest);
    }
    wc_Sha3_256_Free(sha);
    ForceZero(sha, sizeof(*sha));

    return ret;
}

int wc_NoiseSrc_GenerateSeed(wc_NoiseSrc* src, byte* output, word32 sz)
{
#ifdef WOLFSSL_SMALL_STACK
    wc_Sha3* sha = NULL;
#else
    wc_Sha3 sha[1];
#endif
    byte digest[WC_NOISE_CHUNK_SZ];
    byte* raw;
    byte* outStart;
    word32 outLen;
    word32 take;
    int i;
    int ret;

    if (src == NULL || output == NULL) {
        return BAD_FUNC_ARG;
    }
    if (sz == 0) {
        return 0;
    }

    /* Kept so a mid-way failure can wipe what already landed: no caller
     * should ever see a partially-filled seed buffer. */
    outStart = output;
    outLen   = sz;

    XMEMSET(digest, 0, sizeof(digest));

    ret = wc_NoiseSrc_Init(src);
    if (ret != 0) {
        goto out;
    }

#ifdef WOLFSSL_SMALL_STACK
    sha = (wc_Sha3*)XMALLOC(sizeof(wc_Sha3), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (sha == NULL) {
        ret = MEMORY_E;
        goto out;
    }
#endif

    while (sz > 0) {
        for (i = 0; i < (int)src->numSrc; i++) {
            raw = src->work + ((word32)i * src->rawPerSrc);

            ret = NoiseSrc_Gather(src, raw, src->rawPerSrc, i);
            if (ret != 0) {
                goto out;
            }
            ret = NoiseSrc_HealthRun(src, &src->health[i], raw,
                                         src->rawPerSrc);
            if (ret != 0) {
                /* The next call reruns this source's startup test. */
                NoiseSrc_HealthReset(&src->health[i]);
                goto out;
            }
        }

        src->chunkCtr++;
        ret = NoiseSrc_Condition(src, sha, digest);
        if (ret != 0) {
            goto out;
        }

        take = (sz < (word32)WC_NOISE_CHUNK_SZ) ? sz
                                                : (word32)WC_NOISE_CHUNK_SZ;
        XMEMCPY(output, digest, take);
        output += take;
        sz -= take;
    }

out:
    if (ret != 0) {
        ForceZero(outStart, outLen);
    }
    ForceZero(digest, sizeof(digest));
    if (src->work != NULL) {
        ForceZero(src->work, src->workSz);
    }
#ifdef WOLFSSL_SMALL_STACK
    XFREE(sha, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return ret;
}

int wc_NoiseSrc_SelfTest(wc_NoiseSrc* src)
{
    /* Tests RAW noise, not conditioned seeds: the hashed chunk counter makes
     * two GenerateSeed() outputs differ even with every source dead. */
    byte* a;
    byte* b;
    word32 len;
    word32 i;
    byte diff;
    int s;
    int ret;

    if (src == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = wc_NoiseSrc_Init(src);
    if (ret != 0) {
        return ret;
    }

    /* Two gathers side by side in the work buffer. */
    len = src->workSz / 2U;
    if (len > 64U) {
        len = 64U;
    }
    if (len == 0U) {
        return BUFFER_E;
    }
    a = src->work;
    b = src->work + len;

    for (s = 0; (ret == 0) && (s < (int)src->numSrc); s++) {
        /* A gather error propagates without touching the test state. */
        ret = NoiseSrc_Gather(src, a, len, s);
        if (ret == 0) {
            ret = NoiseSrc_Gather(src, b, len, s);
        }
        if (ret != 0) {
            break;
        }

        /* A source stuck at any constant - including one whose clock was
         * never enabled - produces identical gathers. */
        /* ConstantCompare, not XMEMCMP: raw pre-conditioning samples. */
        if (ConstantCompare(a, b, (int)len) == 0) {
            ret = ENTROPY_RT_E;
        }
        else {
            /* Constant-octet check, accumulated rather than early-exit. */
            diff = 0;
            for (i = 1; i < len; i++) {
                diff |= (byte)(a[i] ^ a[0]);
            }
            if (diff == 0) {
                ret = ENTROPY_RT_E;
            }
        }
        if (ret != 0) {
            /* The source must pass its startup test again before it feeds
             * the conditioner. */
            NoiseSrc_HealthReset(&src->health[s]);
        }
    }

    ForceZero(src->work, src->workSz);

    return ret;
}

#endif /* WOLFSSL_NOISE_SRC */
