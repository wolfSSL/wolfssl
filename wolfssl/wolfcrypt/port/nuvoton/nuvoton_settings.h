/* nuvoton_settings.h
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

/* Build settings for the Nuvoton NuMicro M2354 port. Macros only, no BSP
 * headers, so settings.h can include it early.
 *
 * WOLFSSL_NUVOTON_M2354 turns the port on and offloads every engine. Name any
 * of these instead and only those are offloaded:
 *       WOLFSSL_NUVOTON_TRNG    - standalone TRNG (rng.h)
 *       WOLFSSL_NUVOTON_HASH    - CRPT SHA-1/224/256/384/512
 *       WOLFSSL_NUVOTON_CIPHER  - CRPT AES (ECB/CBC/CTR)
 *       WOLFSSL_NUVOTON_ECC     - CRPT ECC, including ECDH
 *       WOLFSSL_NUVOTON_RSA     - CRPT RSA
 *       WOLFSSL_NUVOTON_KS      - Key Store wrapped keys
 *
 * Exactly one TrustZone model, defaulting to the secure world:
 *       WOLFSSL_NUVOTON_SECURE  - direct BSP calls
 *       WOLFSSL_NUVOTON_NSC     - through cmse_nonsecure_entry veneers;
 *                                 nuvoton_hw.c is not compiled and the
 *                                 veneers satisfy wc_nuvoton_hw_* instead
 *
 * Also: WOLFSSL_NUVOTON_DEVID (default 820), WOLFSSL_NUVOTON_DMA_BUF_SZ,
 *       WOLFSSL_NUVOTON_GCM_BUF_SZ,
 * WOLFSSL_NUVOTON_HW_TIMEOUT, WOLFSSL_NUVOTON_RNG_OFFLOAD.
 */

#ifndef WOLFSSL_NUVOTON_SETTINGS_H
#define WOLFSSL_NUVOTON_SETTINGS_H

#ifdef WOLFSSL_NUVOTON_M2354

/* The port works through the wolfSSL crypto callback. */
#ifndef WOLF_CRYPTO_CB
    #define WOLF_CRYPTO_CB
#endif

/* Hash contexts are copied and freed; keys carry a Key Store handle. */
#ifndef WOLF_CRYPTO_CB_COPY
    #define WOLF_CRYPTO_CB_COPY
#endif
#ifndef WOLF_CRYPTO_CB_FREE
    #define WOLF_CRYPTO_CB_FREE
#endif

/* Which world wolfCrypt is built for. Guessing wrong faults on the first CRPT
 * access, so a conflict is an error. Silence means the secure world, where a
 * non-TrustZone application also runs. */
#if defined(WOLFSSL_NUVOTON_SECURE) && defined(WOLFSSL_NUVOTON_NSC)
    #error "Name only one of WOLFSSL_NUVOTON_SECURE or WOLFSSL_NUVOTON_NSC"
#endif
#if !defined(WOLFSSL_NUVOTON_SECURE) && !defined(WOLFSSL_NUVOTON_NSC)
    #define WOLFSSL_NUVOTON_SECURE
#endif

/* Whether ECC was asked for by name rather than coming from the default set
 * below. Only a request by name is worth an error under NO_ASN. */
#ifdef WOLFSSL_NUVOTON_ECC
    #define WOLFSSL_NUVOTON_ECC_BY_NAME
#endif

/* No engine was named, so turn them all on. */
#if !defined(WOLFSSL_NUVOTON_TRNG)   && \
    !defined(WOLFSSL_NUVOTON_HASH)   && \
    !defined(WOLFSSL_NUVOTON_CIPHER) && \
    !defined(WOLFSSL_NUVOTON_ECC)    && \
    !defined(WOLFSSL_NUVOTON_RSA)    && \
    !defined(WOLFSSL_NUVOTON_KS)
    #define WOLFSSL_NUVOTON_TRNG
    #define WOLFSSL_NUVOTON_HASH
    #define WOLFSSL_NUVOTON_CIPHER
    /* Leave RSA off in a build without RSA. */
    #ifndef NO_RSA
        #define WOLFSSL_NUVOTON_RSA
    #endif
    /* HAVE_ECC is decided later, so set this now and let nuvoton_cb_pk.c
     * check. Leave ECC off without ASN.1, the way RSA is left off without
     * RSA: ECDSA crosses this port as DER. */
    #ifndef NO_ASN
        #define WOLFSSL_NUVOTON_ECC
    #endif
    #define WOLFSSL_NUVOTON_KS
#endif

/* The SHA engine needs at least one SHA type. If a build named
 * WOLFSSL_NUVOTON_HASH but disabled them all, leave hashing in software, the
 * way an RSA-less build leaves WOLFSSL_NUVOTON_RSA off. */
#if defined(WOLFSSL_NUVOTON_HASH) && defined(NO_SHA) && defined(NO_SHA256) && \
    !defined(WOLFSSL_SHA224) && !defined(WOLFSSL_SHA384) && \
    !defined(WOLFSSL_SHA512)
    #undef WOLFSSL_NUVOTON_HASH
#endif

/* The TRNG offload only feeds the RNG and seed crypto callbacks, whose
 * wc_CryptoInfo members do not exist under WC_NO_RNG. Leave it off there rather
 * than fail to compile nuvoton_cb_rng.c. */
#if defined(WOLFSSL_NUVOTON_TRNG) && defined(WC_NO_RNG)
    #undef WOLFSSL_NUVOTON_TRNG
#endif

/* The engine buffers the message and never updates the software digest, so
 * the raw-state finals (wc_ShaXxxFinalRaw), which the TLS CBC record MAC
 * uses, would read a stale IV. Force the non-raw MAC path. */
#ifdef WOLFSSL_NUVOTON_HASH
    #undef  WOLFSSL_NO_HASH_RAW
    #define WOLFSSL_NO_HASH_RAW
#endif

/* The port declines the empty message and the SHA-512/224 and /256 variants to
 * software, so it cannot be the only SHA provider. */
#if defined(WOLFSSL_NUVOTON_HASH) && (defined(WOLF_CRYPTO_CB_ONLY_SHA) || \
    defined(WOLF_CRYPTO_CB_ONLY_SHA256) || defined(WOLF_CRYPTO_CB_ONLY_SHA512))
    #error "WOLFSSL_NUVOTON_HASH needs a software SHA fallback; \
WOLF_CRYPTO_CB_ONLY_SHA* is unsupported"
#endif

/* Key Store wrapped keys can be dropped for code size, like the AEAD engines,
 * even when the default engine set is on. */
#ifdef WOLFSSL_NUVOTON_NO_KS
    #undef WOLFSSL_NUVOTON_KS
#endif

/* KS is secure-world only: M2354.h aliases it to KS_S unconditionally, with
 * no KS_NS, unlike CRPT. A non-secure build reaches it through the veneers.
 * Key handles ride in devCtx rather than in a new struct member.
 *
 * That handle outlives the call that installed it, and nothing in wolfCrypt
 * clears devCtx on an ordinary wc_AesSetKey(): the raw key would land in
 * aes->devKey while the cipher callback still saw a stored key and used it
 * instead. The AES set-key hook is the supported way to see that transition,
 * so turn it on - it also makes wc_AesFree() clear devCtx. */
#if defined(WOLFSSL_NUVOTON_KS) && defined(WOLFSSL_NUVOTON_CIPHER) && \
    !defined(NO_AES) && !defined(WOLF_CRYPTO_CB_AES_SETKEY)
    #define WOLF_CRYPTO_CB_AES_SETKEY
#endif

/* SHA-512/224 and /256 are on by DEFAULT (gated on the negative
 * WOLFSSL_NOSHA512_224/_256). The engine does full SHA-512 only, and the
 * hashType member that tells them apart exists solely under
 * WOLFSSL_SHA512_HASHTYPE. Without it the port cannot decline them and
 * answers with a full SHA-512 digest and no error. */
#if defined(WOLFSSL_NUVOTON_HASH) && !defined(NO_SHA512)
    #ifdef WOLFSSL_NO_SHA512_HASHTYPE
        #error "WOLFSSL_NUVOTON_HASH needs WOLFSSL_SHA512_HASHTYPE to tell \
SHA-512 from SHA-512/224 and SHA-512/256"
    #endif
    #ifndef WOLFSSL_SHA512_HASHTYPE
        #define WOLFSSL_SHA512_HASHTYPE
    #endif
#endif

/* ECDSA signatures cross this port as DER, so the engine's r and s go through
 * StoreECC_DSA_Sig() and DecodeECC_DSA_Sig(). Those are ASN.1 and are not
 * built with NO_ASN, where software ECDSA emits and accepts a raw r || s
 * instead. Say so rather than fail to compile, or silently offer an
 * incompatible signature format. ECDH and key generation do not go near them,
 * so only the signing engine has to go. */
#if defined(WOLFSSL_NUVOTON_ECC_BY_NAME) && defined(NO_ASN)
    #error "WOLFSSL_NUVOTON_ECC needs ASN.1 for ECDSA signatures. Drop NO_ASN\
, or drop WOLFSSL_NUVOTON_ECC and leave ECC in software."
#endif

/* The CRPT ECC and RSA drivers take NUL terminated hex strings, so reuse the
 * converter asn.c has for the custom ECC curve parameters. It is deliberately
 * outside asn.c's NO_ASN gate: it converts bytes to characters and uses no
 * ASN.1, so the RSA engine stays available in a no-ASN build. */
#if (defined(WOLFSSL_NUVOTON_ECC) || defined(WOLFSSL_NUVOTON_RSA)) && \
    !defined(WOLFSSL_ASN_HEX_STRING)
    #define WOLFSSL_ASN_HEX_STRING
#endif

/* mp_tohex()/mp_toradix() are gated on WC_MP_TO_RADIX, which nothing RSA
 * pulls in. The engine takes hex, so force it on for the same reason as
 * WOLFSSL_ASN_HEX_STRING above. */
#if (defined(WOLFSSL_NUVOTON_ECC) || defined(WOLFSSL_NUVOTON_RSA)) && \
    !defined(WC_MP_TO_RADIX)
    #define WC_MP_TO_RADIX
#endif

/* Clear of the other ports' defaults (STM32 806-808, RealTek 810-811). */
#ifndef WOLFSSL_NUVOTON_DEVID
    #define WOLFSSL_NUVOTON_DEVID 820
#endif

/* So the stock test and benchmark drive the port with no extra argument. */
/* Every engine call and the static staging buffers are serialised with
 * wolfSSL_CryptHwMutex*, which compile to nothing unless this is on. There is
 * one CRPT channel, so without it two threads overwrite one another's state
 * and their buffers. Define WOLFSSL_NUVOTON_NO_HW_MUTEX to opt out, which is
 * only safe single threaded. */
#if !defined(WOLFSSL_CRYPT_HW_MUTEX) && \
    !defined(WOLFSSL_NUVOTON_NO_HW_MUTEX) && !defined(SINGLE_THREADED)
    #define WOLFSSL_CRYPT_HW_MUTEX 1
#endif

#ifndef WC_USE_DEVID
    #define WC_USE_DEVID WOLFSSL_NUVOTON_DEVID
#endif

/* AES-GCM on the engine. Needs the packed packet staging buffers in
 * nuvoton_hw.c, so it can be turned off on a part where that memory matters;
 * GCM then runs in software. */
#if defined(HAVE_AESGCM) && !defined(NO_AES) && \
    !defined(WOLFSSL_NUVOTON_NO_AESGCM)
    #undef  WOLFSSL_NUVOTON_AESGCM
    #define WOLFSSL_NUVOTON_AESGCM
#endif

/* Bounce buffer for AES operands the engine cannot address. Largest chunk per
 * DMA round; must be a multiple of the AES block size. Raising it trades
 * static SRAM for fewer rounds. */
#ifndef WOLFSSL_NUVOTON_DMA_BUF_SZ
    #define WOLFSSL_NUVOTON_DMA_BUF_SZ (16 * 6)
#endif
#if (WOLFSSL_NUVOTON_DMA_BUF_SZ % 16) != 0
    #error "WOLFSSL_NUVOTON_DMA_BUF_SZ must be a multiple of the AES block size"
#endif

/* Packed AES-GCM staging buffer, the one-shot/cascade boundary. Must be a
 * multiple of the AES block size and large enough for a minimal packet. */
#ifndef WOLFSSL_NUVOTON_GCM_BUF_SZ
    #define WOLFSSL_NUVOTON_GCM_BUF_SZ 1088
#endif
#if (WOLFSSL_NUVOTON_GCM_BUF_SZ % 16) != 0 || WOLFSSL_NUVOTON_GCM_BUF_SZ < 64
    #error "WOLFSSL_NUVOTON_GCM_BUF_SZ must be a multiple of 16 and at least 64"
#endif

/* Busy-wait bound, in loop iterations, so a wedged engine returns an error
 * rather than hanging the caller. AES, SHA and RSA poll; only ECC needs the
 * interrupt (see wc_nuvoton_hw_init). */
#ifndef WOLFSSL_NUVOTON_HW_TIMEOUT
    #define WOLFSSL_NUVOTON_HW_TIMEOUT 5000000
#endif

/* Cortex-M23 is Thumb-1. Both halves matter: the tier without the assembly
 * leaves everything that misses the accelerator on portable C, which dominates
 * at 96 MHz. sp_armthumb.c is Thumb-1; sp_cortexm.c is Thumb-2 and will not
 * assemble here. No Thumb-1 per-algorithm asm exists, so WOLFSSL_ARMASM stays
 * off. See doc/ASM_AND_MATH_DEFINES.md. */
#if !defined(WOLFSSL_SP_ARM_THUMB) && !defined(WOLFSSL_SP_ARM_CORTEX_M) && \
    !defined(WOLFSSL_SP_ARM32) && !defined(WOLFSSL_SP_ARM64) && \
    !defined(WOLFSSL_SP_X86_64) && !defined(WOLFSSL_SP_MATH_ALL) && \
    !defined(WOLFSSL_NUVOTON_NO_SP_DEFAULT)
    #define WOLFSSL_SP_ARM_THUMB
    #ifndef NO_ASM
        #define WOLFSSL_SP_ARM_THUMB_ASM
    #endif
#endif

/* No filesystem and no OS entropy device on this part, so drop /dev/random -
 * but only when the TRNG arm in random.c is compiled, or the build would have
 * no seed source at all. Naming engines without WOLFSSL_NUVOTON_TRNG means
 * supplying wc_GenerateSeed() yourself. */
#ifdef WOLFSSL_NUVOTON_TRNG
    #ifndef NO_DEV_RANDOM
        #define NO_DEV_RANDOM
    #endif
#endif

#endif /* WOLFSSL_NUVOTON_M2354 */

#endif /* WOLFSSL_NUVOTON_SETTINGS_H */
