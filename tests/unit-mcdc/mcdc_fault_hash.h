/* mcdc_fault_hash.h
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

/*
 * mcdc_fault_hash.h -- header-only, self-contained HASH/BLOCK-CIPHER primitive
 * fault injector for the per-module MC/DC campaign. It is the second lever
 * beside mcdc_fault_alloc.h, and the ONLY one that works for the hash-based
 * signature/KEM engines.
 *
 * WHY A SECOND LEVER
 * ------------------
 * The dominant justified-residual class campaign-wide is the FALSE half of a
 * success chain:
 *
 *     if ((ret == 0) && <next step fails>) ...
 *     for (i = 0; (ret == 0) && (i < n); i++) ...
 *     while ((ret == 0) && ...) ...
 *
 * For heap-driven code mcdc_fault_alloc.h breaks the chain by failing the n-th
 * XMALLOC. But wc_lms_impl.c, wc_xmss_impl.c, wc_slhdsa.c and
 * wc_frodokem_mat.c contain ZERO (or nearly zero) allocations: their `ret`
 * comes exclusively from SHA-2 / SHA-3(SHAKE) / AES-ECB primitive calls, and
 * sha256.c / sha512.c / sha3.c never touch the allocator on the paths those
 * engines take. No heap-fault index can make them fail -- see the long note in
 * test_frodokem_fault_common.h, which names this technique as the missing one.
 *
 * HOW IT WORKS -- MACRO INTERPOSITION
 * -----------------------------------
 * Every white-box TU in this campaign #includes the involved .c directly, and
 * the harness links it against libwolfssl.a with only that one object trimmed.
 * The primitives above therefore still come from the archive and cannot be
 * replaced at link time -- but they CAN be replaced at preprocessing time,
 * for this translation unit only:
 *
 *     #include "mcdc_fault_hash.h"           <-- wrappers + macros
 *     #include <wolfcrypt/src/wc_lms_impl.c> <-- sees the macros
 *
 * This header first #includes the real wolfSSL hash/AES headers and defines
 * static wrapper functions that call the REAL primitives, and only THEN
 * #defines the primitive names to the wrappers. Ordering is load-bearing: the
 * wrappers are compiled before the macros exist, so they still reach the real
 * implementations, and the API declarations in the headers are never rewritten.
 * (Same trick as test_tsp_fault_whitebox.c's XGMTIME mock, generalised.)
 *
 * INTENDED SWEEP PATTERN
 * ----------------------
 *     mcdc_fh_disarm();                 -- baseline: everything succeeds
 *     Lifecycle(...);                   -- the TRUE half of every guard
 *     total = mcdc_fh_seen();           -- how many primitive calls that took
 *     for (n = 1; n <= total; n += stride) {
 *         mcdc_fh_arm(n);               -- n-th primitive call (and every later
 *         (void)Lifecycle(...);            one) returns BAD_FUNC_ARG
 *         mcdc_fh_disarm();
 *     }
 *
 * Semantics match mcdc_fault_alloc.h exactly: arm(n) fails call n AND every
 * later one, so an armed region must span ONE operation whose inputs were
 * built while disarmed. Because ret propagates and short-circuits the chain,
 * failing "from n onwards" is what actually drives the (ret == 0) operand
 * false at every downstream decision the operation would have reached.
 *
 * CRASH SAFETY
 * ------------
 * A faulted primitive leaves its output buffer untouched, exactly as a real
 * hardware/driver failure would. The engine under test must propagate the
 * error and clean up -- exercising that propagation is the entire point. The
 * harness must never consume an output produced by an armed call.
 *
 * PORTABILITY
 * -----------
 * Each wrapper/macro pair is behind the same feature guard as the declaration
 * it shadows, so a TU that includes this header builds under every campaign
 * variant (in a build where a primitive is compiled out, nothing is
 * interposed). Unused wrappers are ordinary unused static helpers.
 *
 * A TU that must NOT interpose a particular family can define
 * MCDC_FH_NO_SHA256 / MCDC_FH_NO_SHA512 / MCDC_FH_NO_SHAKE / MCDC_FH_NO_AES /
 * MCDC_FH_NO_HMAC before including this header.
 *
 * The context-INIT calls are opt-in instead of opt-out, because a white-box
 * that builds its own hash objects during setup must not have that setup
 * faulted: MCDC_FH_WITH_SHAKE_INIT adds wc_InitShake128/256 and
 * MCDC_FH_WITH_SHA_INIT adds wc_InitSha256/512.
 */

#ifndef MCDC_FAULT_HASH_H
#define MCDC_FAULT_HASH_H

/* Must be first: establishes BUILDING_WOLFSSL / config.h exactly the way every
 * wolfcrypt .c does, so including this header before the involved .c does not
 * change how that .c sees the world. */
#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#if !defined(NO_SHA256) && !defined(MCDC_FH_NO_SHA256)
    #include <wolfssl/wolfcrypt/sha256.h>
    #define MCDC_FH_HAVE_SHA256
#endif
#if defined(WOLFSSL_SHA512) && !defined(MCDC_FH_NO_SHA512)
    #include <wolfssl/wolfcrypt/sha512.h>
    #define MCDC_FH_HAVE_SHA512
#endif
#if (defined(WOLFSSL_SHAKE128) || defined(WOLFSSL_SHAKE256)) && \
    !defined(MCDC_FH_NO_SHAKE)
    #include <wolfssl/wolfcrypt/sha3.h>
    #define MCDC_FH_HAVE_SHAKE
#endif
#if !defined(NO_AES) && !defined(MCDC_FH_NO_AES)
    #include <wolfssl/wolfcrypt/aes.h>
    #define MCDC_FH_HAVE_AES
#endif
#if !defined(NO_HMAC) && !defined(MCDC_FH_NO_HMAC)
    #include <wolfssl/wolfcrypt/hmac.h>
    #define MCDC_FH_HAVE_HMAC
#endif

/* Error the faulted primitive reports. Any non-zero value drives the
 * (ret == 0) operand false; BAD_FUNC_ARG is defined by error-crypt.h in every
 * configuration and is already the code these engines propagate for a rejected
 * primitive call. */
#define MCDC_FH_ERR   BAD_FUNC_ARG

/* Not every interposer is used by every white-box / variant; silence the
 * -Wunused-function noise that would otherwise swamp the wb build logs. */
#if defined(__GNUC__) || defined(__clang__)
    #define MCDC_FH_MAYBE_UNUSED __attribute__((unused))
#else
    #define MCDC_FH_MAYBE_UNUSED
#endif

/* file-static injector state (one TU per white-box, so file scope is fine) */
static long mcdc_fh_count   = 0;  /* primitive calls seen since arm/disarm */
static long mcdc_fh_fail_at = 0;  /* fail from this index on; 0 = off      */

/* Count this call; report whether it must fail. */
MCDC_FH_MAYBE_UNUSED static int mcdc_fh_hit(void)
{
    mcdc_fh_count++;
    return (mcdc_fh_fail_at != 0) && (mcdc_fh_count >= mcdc_fh_fail_at);
}

/* Arm: the n-th primitive call from now on (and every later one) fails. */
MCDC_FH_MAYBE_UNUSED static void mcdc_fh_arm(long n)
{
    mcdc_fh_count   = 0;
    mcdc_fh_fail_at = (n > 0) ? n : 0;
}

/* Disarm and reset the counter, so a following unarmed run can be measured. */
MCDC_FH_MAYBE_UNUSED static void mcdc_fh_disarm(void)
{
    mcdc_fh_fail_at = 0;
    mcdc_fh_count   = 0;
}

/* Primitive calls counted since the last arm()/disarm(). Used to size a
 * sweep: run the target disarmed, then sweep 1..mcdc_fh_seen(). */
MCDC_FH_MAYBE_UNUSED static long mcdc_fh_seen(void)
{
    return mcdc_fh_count;
}

/* ---------------- SHA-256 ---------------- */
#ifdef MCDC_FH_HAVE_SHA256
/* wc_InitSha256/512 are OPT-IN (MCDC_FH_WITH_SHA_INIT) for the same reason the
 * SHAKE ones are: a white-box that builds its own hash objects for test setup
 * must not have those setup calls faulted. wc_slhdsa.c needs them, because its
 * `if ((ret == 0) && (key->params->n > 16))` guard in wc_SlhDsaKey_Init() takes
 * its ret from wc_InitSha256() and nothing else. */
#ifdef MCDC_FH_WITH_SHA_INIT
MCDC_FH_MAYBE_UNUSED static int mcdc_fh_InitSha256(wc_Sha256* sha)
{
    if (mcdc_fh_hit())
        return MCDC_FH_ERR;
    return wc_InitSha256(sha);
}
#endif
MCDC_FH_MAYBE_UNUSED static int mcdc_fh_Sha256Update(wc_Sha256* sha, const byte* data, word32 len)
{
    if (mcdc_fh_hit())
        return MCDC_FH_ERR;
    return wc_Sha256Update(sha, data, len);
}
MCDC_FH_MAYBE_UNUSED static int mcdc_fh_Sha256Final(wc_Sha256* sha, byte* hash)
{
    if (mcdc_fh_hit())
        return MCDC_FH_ERR;
    return wc_Sha256Final(sha, hash);
}
#if defined(WOLFSSL_HAVE_LMS) && !defined(WOLFSSL_LMS_FULL_HASH)
MCDC_FH_MAYBE_UNUSED static int mcdc_fh_Sha256HashBlock(wc_Sha256* sha, const unsigned char* data,
    unsigned char* hash)
{
    if (mcdc_fh_hit())
        return MCDC_FH_ERR;
    return wc_Sha256HashBlock(sha, data, hash);
}
#endif
#endif /* MCDC_FH_HAVE_SHA256 */

/* ---------------- SHA-512 ---------------- */
#ifdef MCDC_FH_HAVE_SHA512
#ifdef MCDC_FH_WITH_SHA_INIT
MCDC_FH_MAYBE_UNUSED static int mcdc_fh_InitSha512(wc_Sha512* sha)
{
    if (mcdc_fh_hit())
        return MCDC_FH_ERR;
    return wc_InitSha512(sha);
}
#endif
MCDC_FH_MAYBE_UNUSED static int mcdc_fh_Sha512Update(wc_Sha512* sha, const byte* data, word32 len)
{
    if (mcdc_fh_hit())
        return MCDC_FH_ERR;
    return wc_Sha512Update(sha, data, len);
}
MCDC_FH_MAYBE_UNUSED static int mcdc_fh_Sha512Final(wc_Sha512* sha, byte* hash)
{
    if (mcdc_fh_hit())
        return MCDC_FH_ERR;
    return wc_Sha512Final(sha, hash);
}
#endif /* MCDC_FH_HAVE_SHA512 */

/* ---------------- SHAKE128 / SHAKE256 ---------------- */
#ifdef MCDC_FH_HAVE_SHAKE
/* The wc_InitShake* interposers are OPT-IN (MCDC_FH_WITH_SHAKE_INIT): a
 * white-box that initialises its own SHAKE contexts for test setup must not
 * have those setup calls faulted. wc_frodokem_mat.c is the case that needs
 * them, because its `if (p->useShake256 && ((ret = wc_InitShake256(...)) == 0))`
 * guard has no other way to take its second operand false. */
#ifdef MCDC_FH_WITH_SHAKE_INIT
#ifdef WOLFSSL_SHAKE128
MCDC_FH_MAYBE_UNUSED static int mcdc_fh_InitShake128(wc_Shake* shake, void* heap, int devId)
{
    if (mcdc_fh_hit())
        return MCDC_FH_ERR;
    return wc_InitShake128(shake, heap, devId);
}
#endif
#ifdef WOLFSSL_SHAKE256
MCDC_FH_MAYBE_UNUSED static int mcdc_fh_InitShake256(wc_Shake* shake, void* heap, int devId)
{
    if (mcdc_fh_hit())
        return MCDC_FH_ERR;
    return wc_InitShake256(shake, heap, devId);
}
#endif
#endif /* MCDC_FH_WITH_SHAKE_INIT */
#ifdef WOLFSSL_SHAKE128
MCDC_FH_MAYBE_UNUSED static int mcdc_fh_Shake128_Update(wc_Shake* shake, const byte* data,
    word32 len)
{
    if (mcdc_fh_hit())
        return MCDC_FH_ERR;
    return wc_Shake128_Update(shake, data, len);
}
MCDC_FH_MAYBE_UNUSED static int mcdc_fh_Shake128_Final(wc_Shake* shake, byte* hash, word32 hashLen)
{
    if (mcdc_fh_hit())
        return MCDC_FH_ERR;
    return wc_Shake128_Final(shake, hash, hashLen);
}
MCDC_FH_MAYBE_UNUSED static int mcdc_fh_Shake128_Absorb(wc_Shake* shake, const byte* data,
    word32 len)
{
    if (mcdc_fh_hit())
        return MCDC_FH_ERR;
    return wc_Shake128_Absorb(shake, data, len);
}
MCDC_FH_MAYBE_UNUSED static int mcdc_fh_Shake128_SqueezeBlocks(wc_Shake* shake, byte* out,
    word32 blockCnt)
{
    if (mcdc_fh_hit())
        return MCDC_FH_ERR;
    return wc_Shake128_SqueezeBlocks(shake, out, blockCnt);
}
#endif /* WOLFSSL_SHAKE128 */
#ifdef WOLFSSL_SHAKE256
MCDC_FH_MAYBE_UNUSED static int mcdc_fh_Shake256_Update(wc_Shake* shake, const byte* data,
    word32 len)
{
    if (mcdc_fh_hit())
        return MCDC_FH_ERR;
    return wc_Shake256_Update(shake, data, len);
}
MCDC_FH_MAYBE_UNUSED static int mcdc_fh_Shake256_Final(wc_Shake* shake, byte* hash, word32 hashLen)
{
    if (mcdc_fh_hit())
        return MCDC_FH_ERR;
    return wc_Shake256_Final(shake, hash, hashLen);
}
MCDC_FH_MAYBE_UNUSED static int mcdc_fh_Shake256_Absorb(wc_Shake* shake, const byte* data,
    word32 len)
{
    if (mcdc_fh_hit())
        return MCDC_FH_ERR;
    return wc_Shake256_Absorb(shake, data, len);
}
MCDC_FH_MAYBE_UNUSED static int mcdc_fh_Shake256_SqueezeBlocks(wc_Shake* shake, byte* out,
    word32 blockCnt)
{
    if (mcdc_fh_hit())
        return MCDC_FH_ERR;
    return wc_Shake256_SqueezeBlocks(shake, out, blockCnt);
}
#endif /* WOLFSSL_SHAKE256 */
#endif /* MCDC_FH_HAVE_SHAKE */

/* ---------------- HMAC (SLH-DSA's SHA-2 PRF_msg / H_msg) ---------------- */
#ifdef MCDC_FH_HAVE_HMAC
MCDC_FH_MAYBE_UNUSED static int mcdc_fh_HmacSetKey(Hmac* hmac, int type,
    const byte* key, word32 keySz)
{
    if (mcdc_fh_hit())
        return MCDC_FH_ERR;
    return wc_HmacSetKey(hmac, type, key, keySz);
}
MCDC_FH_MAYBE_UNUSED static int mcdc_fh_HmacUpdate(Hmac* hmac, const byte* in,
    word32 sz)
{
    if (mcdc_fh_hit())
        return MCDC_FH_ERR;
    return wc_HmacUpdate(hmac, in, sz);
}
MCDC_FH_MAYBE_UNUSED static int mcdc_fh_HmacFinal(Hmac* hmac, byte* out)
{
    if (mcdc_fh_hit())
        return MCDC_FH_ERR;
    return wc_HmacFinal(hmac, out);
}
#endif /* MCDC_FH_HAVE_HMAC */

/* ---------------- AES-ECB (FrodoKEM matrix generation) ---------------- */
#if defined(MCDC_FH_HAVE_AES) && defined(HAVE_AES_ECB)
MCDC_FH_MAYBE_UNUSED static int mcdc_fh_AesEcbEncrypt(Aes* aes, byte* out, const byte* in,
    word32 sz)
{
    if (mcdc_fh_hit())
        return MCDC_FH_ERR;
    return wc_AesEcbEncrypt(aes, out, in, sz);
}
#endif
#if defined(MCDC_FH_HAVE_AES) && defined(WOLFSSL_AES_DIRECT)
MCDC_FH_MAYBE_UNUSED static int mcdc_fh_AesSetKeyDirect(Aes* aes, const byte* key, word32 len,
    const byte* iv, int dir)
{
    if (mcdc_fh_hit())
        return MCDC_FH_ERR;
    return wc_AesSetKeyDirect(aes, key, len, iv, dir);
}
#endif

/* ------------------------------------------------------------------------
 * Install the interposers. Everything above is already compiled against the
 * REAL primitives; from here on the name means the wrapper. The involved .c
 * must be #included AFTER this point.
 * ---------------------------------------------------------------------- */
#ifdef MCDC_FH_HAVE_SHA256
    #ifdef MCDC_FH_WITH_SHA_INIT
        #undef  wc_InitSha256
        #define wc_InitSha256(a)          mcdc_fh_InitSha256((a))
    #endif
    #undef  wc_Sha256Update
    #define wc_Sha256Update(a, b, c)      mcdc_fh_Sha256Update((a), (b), (c))
    #undef  wc_Sha256Final
    #define wc_Sha256Final(a, b)          mcdc_fh_Sha256Final((a), (b))
    #if defined(WOLFSSL_HAVE_LMS) && !defined(WOLFSSL_LMS_FULL_HASH)
        #undef  wc_Sha256HashBlock
        #define wc_Sha256HashBlock(a, b, c) \
            mcdc_fh_Sha256HashBlock((a), (b), (c))
    #endif
#endif

#ifdef MCDC_FH_HAVE_SHA512
    #ifdef MCDC_FH_WITH_SHA_INIT
        #undef  wc_InitSha512
        #define wc_InitSha512(a)          mcdc_fh_InitSha512((a))
    #endif
    #undef  wc_Sha512Update
    #define wc_Sha512Update(a, b, c)      mcdc_fh_Sha512Update((a), (b), (c))
    #undef  wc_Sha512Final
    #define wc_Sha512Final(a, b)          mcdc_fh_Sha512Final((a), (b))
#endif

#ifdef MCDC_FH_HAVE_SHAKE
#ifdef MCDC_FH_WITH_SHAKE_INIT
    #ifdef WOLFSSL_SHAKE128
        #undef  wc_InitShake128
        #define wc_InitShake128(a, b, c)  mcdc_fh_InitShake128((a), (b), (c))
    #endif
    #ifdef WOLFSSL_SHAKE256
        #undef  wc_InitShake256
        #define wc_InitShake256(a, b, c)  mcdc_fh_InitShake256((a), (b), (c))
    #endif
#endif
#ifdef WOLFSSL_SHAKE128
    #undef  wc_Shake128_Update
    #define wc_Shake128_Update(a, b, c)   mcdc_fh_Shake128_Update((a), (b), (c))
    #undef  wc_Shake128_Final
    #define wc_Shake128_Final(a, b, c)    mcdc_fh_Shake128_Final((a), (b), (c))
    #undef  wc_Shake128_Absorb
    #define wc_Shake128_Absorb(a, b, c)   mcdc_fh_Shake128_Absorb((a), (b), (c))
    #undef  wc_Shake128_SqueezeBlocks
    #define wc_Shake128_SqueezeBlocks(a, b, c) \
        mcdc_fh_Shake128_SqueezeBlocks((a), (b), (c))
#endif
#ifdef WOLFSSL_SHAKE256
    #undef  wc_Shake256_Update
    #define wc_Shake256_Update(a, b, c)   mcdc_fh_Shake256_Update((a), (b), (c))
    #undef  wc_Shake256_Final
    #define wc_Shake256_Final(a, b, c)    mcdc_fh_Shake256_Final((a), (b), (c))
    #undef  wc_Shake256_Absorb
    #define wc_Shake256_Absorb(a, b, c)   mcdc_fh_Shake256_Absorb((a), (b), (c))
    #undef  wc_Shake256_SqueezeBlocks
    #define wc_Shake256_SqueezeBlocks(a, b, c) \
        mcdc_fh_Shake256_SqueezeBlocks((a), (b), (c))
#endif
#endif /* MCDC_FH_HAVE_SHAKE */

#ifdef MCDC_FH_HAVE_HMAC
    #undef  wc_HmacSetKey
    #define wc_HmacSetKey(a, b, c, d)     mcdc_fh_HmacSetKey((a), (b), (c), (d))
    #undef  wc_HmacUpdate
    #define wc_HmacUpdate(a, b, c)        mcdc_fh_HmacUpdate((a), (b), (c))
    #undef  wc_HmacFinal
    #define wc_HmacFinal(a, b)            mcdc_fh_HmacFinal((a), (b))
#endif

#if defined(MCDC_FH_HAVE_AES) && defined(HAVE_AES_ECB)
    #undef  wc_AesEcbEncrypt
    #define wc_AesEcbEncrypt(a, b, c, d)  mcdc_fh_AesEcbEncrypt((a), (b), (c), (d))
#endif
#if defined(MCDC_FH_HAVE_AES) && defined(WOLFSSL_AES_DIRECT)
    #undef  wc_AesSetKeyDirect
    #define wc_AesSetKeyDirect(a, b, c, d, e) \
        mcdc_fh_AesSetKeyDirect((a), (b), (c), (d), (e))
#endif

#endif /* MCDC_FAULT_HASH_H */
