/* stm32.h
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

#ifndef _WOLFPORT_STM32_H_
#define _WOLFPORT_STM32_H_

/* Generic STM32 Hashing and Crypto Functions */
/* Supports CubeMX HAL, Standard Peripheral Library, or bare-metal direct
 * register access (WOLFSSL_STM32_BARE). */

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h> /* for MATH_INT_T */

/* STM32H563 has a reduced "light" PKA: it performs ECDSA signature
 * verification but not signing (per ST -- the H563 datasheet sec. 3.32
 * lists ECDSA verification only; H573 supports full sign + verify).
 * Auto-enable verify-only so wc_ecc_sign_hash routes to software while
 * wc_ecc_verify_hash stays on the HW PKA. STM32H573xx keeps full PKA.
 * Define WC_STM32_PKA_VERIFY_ONLY yourself for any other verify-only part. */
#if defined(WOLFSSL_STM32_PKA) && defined(STM32H563xx) && \
    !defined(STM32H573xx) && !defined(WC_STM32_PKA_VERIFY_ONLY)
    #define WC_STM32_PKA_VERIFY_ONLY
#endif

#ifdef WOLFSSL_STM32_BARE
/* Per-family direct-register clock-enable macros. CMSIS device header is
 * already included via settings.h. RCC->...ENR bit names come from CMSIS.
 *
 * Clock enable/disable share one idiom across families: OR (enable) or
 * AND-NOT (disable) the RCC enable register, with a read-back after enable
 * so the bit is committed before the peripheral is touched. WC_STM32_CLK_EN
 * / WC_STM32_CLK_DIS centralize that idiom; each family arm below just maps
 * its peripheral macros onto the right RCC register + bit. (The MP13 arm
 * keeps its own form -- it uses separate set/clear registers.) */
#define WC_STM32_CLK_EN(reg, bit) \
    do { RCC->reg |= (bit); (void)RCC->reg; } while (0)
#define WC_STM32_CLK_DIS(reg, bit) \
    do { RCC->reg &= ~(bit); } while (0)

#if defined(WOLFSSL_STM32H5)
    #define WC_STM32_AES_CLK_ENABLE() \
        WC_STM32_CLK_EN(AHB2ENR, RCC_AHB2ENR_AESEN)
    #define WC_STM32_AES_CLK_DISABLE() \
        WC_STM32_CLK_DIS(AHB2ENR, RCC_AHB2ENR_AESEN)
    #ifdef RCC_AHB2ENR_SAESEN
        #define WC_STM32_SAES_CLK_ENABLE() \
            WC_STM32_CLK_EN(AHB2ENR, RCC_AHB2ENR_SAESEN)
        #define WC_STM32_SAES_CLK_DISABLE() \
            WC_STM32_CLK_DIS(AHB2ENR, RCC_AHB2ENR_SAESEN)
    #endif
    #define WC_STM32_HASH_CLK_ENABLE() \
        WC_STM32_CLK_EN(AHB2ENR, RCC_AHB2ENR_HASHEN)
    #define WC_STM32_HASH_CLK_DISABLE() \
        WC_STM32_CLK_DIS(AHB2ENR, RCC_AHB2ENR_HASHEN)
    #define WC_STM32_RNG_CLK_ENABLE() \
        WC_STM32_CLK_EN(AHB2ENR, RCC_AHB2ENR_RNGEN)
#elif defined(WOLFSSL_STM32F2) || defined(WOLFSSL_STM32F4) || \
      defined(WOLFSSL_STM32F7) || defined(WOLFSSL_STM32H7)
    /* F2/F4/F7/H7 -- CRYP + HASH + RNG all on AHB2 with identical
     * RCC bit names. */
    #define WC_STM32_AES_CLK_ENABLE() \
        WC_STM32_CLK_EN(AHB2ENR, RCC_AHB2ENR_CRYPEN)
    #define WC_STM32_AES_CLK_DISABLE() \
        WC_STM32_CLK_DIS(AHB2ENR, RCC_AHB2ENR_CRYPEN)
    #define WC_STM32_HASH_CLK_ENABLE() \
        WC_STM32_CLK_EN(AHB2ENR, RCC_AHB2ENR_HASHEN)
    #define WC_STM32_HASH_CLK_DISABLE() \
        WC_STM32_CLK_DIS(AHB2ENR, RCC_AHB2ENR_HASHEN)
    #define WC_STM32_RNG_CLK_ENABLE() \
        WC_STM32_CLK_EN(AHB2ENR, RCC_AHB2ENR_RNGEN)
#elif defined(WOLFSSL_STM32MP13)
    /* MP13 -- CRYP1/HASH1/RNG1 on AHB5; CMSIS device header may use
     * symbol-suffixed RCC names. Gate each macro on the CMSIS bit so
     * a partial device header still compiles. Separate set/clear
     * registers, so this arm keeps its own form. */
    #if defined(RCC_MP_AHB5ENSETR_CRYP1EN)
        #define WC_STM32_AES_CLK_ENABLE() \
            do { RCC->MP_AHB5ENSETR |= RCC_MP_AHB5ENSETR_CRYP1EN; \
                 (void)RCC->MP_AHB5ENSETR; } while (0)
        #define WC_STM32_AES_CLK_DISABLE() \
            do { RCC->MP_AHB5ENCLRR = RCC_MP_AHB5ENSETR_CRYP1EN; } while (0)
    #endif
    #if defined(RCC_MP_AHB5ENSETR_HASH1EN)
        #define WC_STM32_HASH_CLK_ENABLE() \
            do { RCC->MP_AHB5ENSETR |= RCC_MP_AHB5ENSETR_HASH1EN; \
                 (void)RCC->MP_AHB5ENSETR; } while (0)
        #define WC_STM32_HASH_CLK_DISABLE() \
            do { RCC->MP_AHB5ENCLRR = RCC_MP_AHB5ENSETR_HASH1EN; } while (0)
    #endif
    #if defined(RCC_MP_AHB5ENSETR_RNG1EN)
        #define WC_STM32_RNG_CLK_ENABLE() \
            do { RCC->MP_AHB5ENSETR |= RCC_MP_AHB5ENSETR_RNG1EN; \
                 (void)RCC->MP_AHB5ENSETR; } while (0)
    #endif
#elif defined(WOLFSSL_STM32L4)
    #define WC_STM32_AES_CLK_ENABLE() \
        WC_STM32_CLK_EN(AHB2ENR, RCC_AHB2ENR_AESEN)
    #define WC_STM32_AES_CLK_DISABLE() \
        WC_STM32_CLK_DIS(AHB2ENR, RCC_AHB2ENR_AESEN)
    #define WC_STM32_HASH_CLK_ENABLE() \
        WC_STM32_CLK_EN(AHB2ENR, RCC_AHB2ENR_HASHEN)
    #define WC_STM32_HASH_CLK_DISABLE() \
        WC_STM32_CLK_DIS(AHB2ENR, RCC_AHB2ENR_HASHEN)
    #define WC_STM32_RNG_CLK_ENABLE() \
        WC_STM32_CLK_EN(AHB2ENR, RCC_AHB2ENR_RNGEN)
#elif defined(WOLFSSL_STM32L5)
    /* L5: HASH + RNG on AHB2 (L552). L562 also adds AES + PKA. AES
     * clock-enable is gated on the CMSIS symbol so headers that don't
     * expose AESEN (L552) skip the define. */
    #ifdef RCC_AHB2ENR_AESEN
        #define WC_STM32_AES_CLK_ENABLE() \
            WC_STM32_CLK_EN(AHB2ENR, RCC_AHB2ENR_AESEN)
        #define WC_STM32_AES_CLK_DISABLE() \
            WC_STM32_CLK_DIS(AHB2ENR, RCC_AHB2ENR_AESEN)
    #endif
    #define WC_STM32_HASH_CLK_ENABLE() \
        WC_STM32_CLK_EN(AHB2ENR, RCC_AHB2ENR_HASHEN)
    #define WC_STM32_HASH_CLK_DISABLE() \
        WC_STM32_CLK_DIS(AHB2ENR, RCC_AHB2ENR_HASHEN)
    #define WC_STM32_RNG_CLK_ENABLE() \
        WC_STM32_CLK_EN(AHB2ENR, RCC_AHB2ENR_RNGEN)
#elif defined(WOLFSSL_STM32U5) || defined(WOLFSSL_STM32U3)
    /* U5 / U3 RCC uses AHB2ENR1 (not AHB2ENR). AES bit only present on
     * variants that have the peripheral (U585+, U385+). SAES is on the
     * same AHB2ENR1; gate on the CMSIS bit so headers without it (e.g.
     * U575 which has neither AES nor SAES) skip. */
    #ifdef RCC_AHB2ENR1_AESEN
        #define WC_STM32_AES_CLK_ENABLE() \
            WC_STM32_CLK_EN(AHB2ENR1, RCC_AHB2ENR1_AESEN)
        #define WC_STM32_AES_CLK_DISABLE() \
            WC_STM32_CLK_DIS(AHB2ENR1, RCC_AHB2ENR1_AESEN)
    #endif
    #ifdef RCC_AHB2ENR1_SAESEN
        #define WC_STM32_SAES_CLK_ENABLE() \
            WC_STM32_CLK_EN(AHB2ENR1, RCC_AHB2ENR1_SAESEN)
        #define WC_STM32_SAES_CLK_DISABLE() \
            WC_STM32_CLK_DIS(AHB2ENR1, RCC_AHB2ENR1_SAESEN)
    #endif
    #ifdef RCC_AHB2ENR1_HASHEN
        #define WC_STM32_HASH_CLK_ENABLE() \
            WC_STM32_CLK_EN(AHB2ENR1, RCC_AHB2ENR1_HASHEN)
        #define WC_STM32_HASH_CLK_DISABLE() \
            WC_STM32_CLK_DIS(AHB2ENR1, RCC_AHB2ENR1_HASHEN)
    #endif
    #define WC_STM32_RNG_CLK_ENABLE() \
        WC_STM32_CLK_EN(AHB2ENR1, RCC_AHB2ENR1_RNGEN)
#elif defined(WOLFSSL_STM32G0)
    #define WC_STM32_AES_CLK_ENABLE() \
        WC_STM32_CLK_EN(AHBENR, RCC_AHBENR_AESEN)
    #define WC_STM32_AES_CLK_DISABLE() \
        WC_STM32_CLK_DIS(AHBENR, RCC_AHBENR_AESEN)
    #define WC_STM32_RNG_CLK_ENABLE() \
        WC_STM32_CLK_EN(AHBENR, RCC_AHBENR_RNGEN)
#elif defined(WOLFSSL_STM32WB)
    /* WB55 dual-core: AES1 is the M4 (CPU1) application AES, on AHB2.
     * AES2 sits on AHB4/AHB3 and is reserved for the M0+ side / shared use.
     * The wolfcrypt port maps CRYP -> AES1 (see CRYP alias above), so use
     * AES1's clock-enable bit. RNG is on AHB3. */
    #define WC_STM32_AES_CLK_ENABLE() \
        WC_STM32_CLK_EN(AHB2ENR, RCC_AHB2ENR_AES1EN)
    #define WC_STM32_AES_CLK_DISABLE() \
        WC_STM32_CLK_DIS(AHB2ENR, RCC_AHB2ENR_AES1EN)
    #define WC_STM32_RNG_CLK_ENABLE() \
        WC_STM32_CLK_EN(AHB3ENR, RCC_AHB3ENR_RNGEN)
#elif defined(WOLFSSL_STM32WL)
    /* WL55 dual-core: TinyAES + RNG + PKA on M4 (CPU1) side. AES on AHB3,
     * RNG on AHB3, PKA on AHB3. No HASH peripheral. V1 PKA layout. */
    #ifdef RCC_AHB3ENR_AESEN
        #define WC_STM32_AES_CLK_ENABLE() \
            WC_STM32_CLK_EN(AHB3ENR, RCC_AHB3ENR_AESEN)
        #define WC_STM32_AES_CLK_DISABLE() \
            WC_STM32_CLK_DIS(AHB3ENR, RCC_AHB3ENR_AESEN)
    #endif
    #define WC_STM32_RNG_CLK_ENABLE() \
        WC_STM32_CLK_EN(AHB3ENR, RCC_AHB3ENR_RNGEN)
#elif defined(WOLFSSL_STM32G4)
    /* G4: TinyAES + RNG + PKA on AHB2. No HASH peripheral. */
    #define WC_STM32_AES_CLK_ENABLE() \
        WC_STM32_CLK_EN(AHB2ENR, RCC_AHB2ENR_AESEN)
    #define WC_STM32_AES_CLK_DISABLE() \
        WC_STM32_CLK_DIS(AHB2ENR, RCC_AHB2ENR_AESEN)
    #define WC_STM32_RNG_CLK_ENABLE() \
        WC_STM32_CLK_EN(AHB2ENR, RCC_AHB2ENR_RNGEN)
#elif defined(WOLFSSL_STM32WBA)
    /* WBA: TinyAES + HASH + RNG + PKA + SAES on AHB2 (PKA on AHB1). */
    #define WC_STM32_AES_CLK_ENABLE() \
        WC_STM32_CLK_EN(AHB2ENR, RCC_AHB2ENR_AESEN)
    #define WC_STM32_AES_CLK_DISABLE() \
        WC_STM32_CLK_DIS(AHB2ENR, RCC_AHB2ENR_AESEN)
    #ifdef RCC_AHB2ENR_SAESEN
        #define WC_STM32_SAES_CLK_ENABLE() \
            WC_STM32_CLK_EN(AHB2ENR, RCC_AHB2ENR_SAESEN)
        #define WC_STM32_SAES_CLK_DISABLE() \
            WC_STM32_CLK_DIS(AHB2ENR, RCC_AHB2ENR_SAESEN)
    #endif
    #ifdef RCC_AHB2ENR_HASHEN
        #define WC_STM32_HASH_CLK_ENABLE() \
            WC_STM32_CLK_EN(AHB2ENR, RCC_AHB2ENR_HASHEN)
        #define WC_STM32_HASH_CLK_DISABLE() \
            WC_STM32_CLK_DIS(AHB2ENR, RCC_AHB2ENR_HASHEN)
    #endif
    #define WC_STM32_RNG_CLK_ENABLE() \
        WC_STM32_CLK_EN(AHB2ENR, RCC_AHB2ENR_RNGEN)
#elif defined(WOLFSSL_STM32C5)
    /* C5: TinyAES + HASH + RNG + SAES + PKA all on AHB2. New-gen HASH IP
     * (4-bit ALGO field, same as H5/U3/N6). */
    #define WC_STM32_AES_CLK_ENABLE() \
        WC_STM32_CLK_EN(AHB2ENR, RCC_AHB2ENR_AESEN)
    #define WC_STM32_AES_CLK_DISABLE() \
        WC_STM32_CLK_DIS(AHB2ENR, RCC_AHB2ENR_AESEN)
    #ifdef RCC_AHB2ENR_SAESEN
        #define WC_STM32_SAES_CLK_ENABLE() \
            WC_STM32_CLK_EN(AHB2ENR, RCC_AHB2ENR_SAESEN)
        #define WC_STM32_SAES_CLK_DISABLE() \
            WC_STM32_CLK_DIS(AHB2ENR, RCC_AHB2ENR_SAESEN)
    #endif
    #define WC_STM32_HASH_CLK_ENABLE() \
        WC_STM32_CLK_EN(AHB2ENR, RCC_AHB2ENR_HASHEN)
    #define WC_STM32_HASH_CLK_DISABLE() \
        WC_STM32_CLK_DIS(AHB2ENR, RCC_AHB2ENR_HASHEN)
    #define WC_STM32_RNG_CLK_ENABLE() \
        WC_STM32_CLK_EN(AHB2ENR, RCC_AHB2ENR_RNGEN)
#elif defined(WOLFSSL_STM32U0)
    /* U0: Cortex-M0+ low-end. AES + RNG only (no SAES, no HASH, no PKA,
     * no CRYP). Both on the single AHBENR. TinyAES IP, KEYSIZE field
     * for 128/256-bit. */
    #define WC_STM32_AES_CLK_ENABLE() \
        WC_STM32_CLK_EN(AHBENR, RCC_AHBENR_AESEN)
    #define WC_STM32_AES_CLK_DISABLE() \
        WC_STM32_CLK_DIS(AHBENR, RCC_AHBENR_AESEN)
    #define WC_STM32_RNG_CLK_ENABLE() \
        WC_STM32_CLK_EN(AHBENR, RCC_AHBENR_RNGEN)
#elif defined(WOLFSSL_STM32N6)
    /* N6: CRYP + HASH + RNG + SAES + PKA all on AHB3. Note that on N6
     * the AES IP is the older "fat" CRYP (with AAD/header handling in
     * register) -- SAES is the newer TinyAES-shape IP and is the one
     * routed by the BARE driver when WOLFSSL_STM32_USE_SAES is set. */
    #ifdef RCC_AHB3ENR_CRYPEN
        #define WC_STM32_AES_CLK_ENABLE() \
            WC_STM32_CLK_EN(AHB3ENR, RCC_AHB3ENR_CRYPEN)
        #define WC_STM32_AES_CLK_DISABLE() \
            WC_STM32_CLK_DIS(AHB3ENR, RCC_AHB3ENR_CRYPEN)
    #endif
    #ifdef RCC_AHB3ENR_SAESEN
        #define WC_STM32_SAES_CLK_ENABLE() \
            WC_STM32_CLK_EN(AHB3ENR, RCC_AHB3ENR_SAESEN)
        #define WC_STM32_SAES_CLK_DISABLE() \
            WC_STM32_CLK_DIS(AHB3ENR, RCC_AHB3ENR_SAESEN)
    #endif
    #define WC_STM32_HASH_CLK_ENABLE() \
        WC_STM32_CLK_EN(AHB3ENR, RCC_AHB3ENR_HASHEN)
    #define WC_STM32_HASH_CLK_DISABLE() \
        WC_STM32_CLK_DIS(AHB3ENR, RCC_AHB3ENR_HASHEN)
    #define WC_STM32_RNG_CLK_ENABLE() \
        WC_STM32_CLK_EN(AHB3ENR, RCC_AHB3ENR_RNGEN)
#elif defined(WOLFSSL_STM32H7S)
    /* H7RS/H7S3: classic H7 fat CRYP + classic H7 HASH (same register
     * shapes as H753) but RCC clock-enable bits moved to AHB3ENR, and
     * V2 PKA + SAES added. All five (CRYP/HASH/RNG/SAES/PKA) live on
     * AHB3ENR. */
    #ifdef RCC_AHB3ENR_CRYPEN
        #define WC_STM32_AES_CLK_ENABLE() \
            WC_STM32_CLK_EN(AHB3ENR, RCC_AHB3ENR_CRYPEN)
        #define WC_STM32_AES_CLK_DISABLE() \
            WC_STM32_CLK_DIS(AHB3ENR, RCC_AHB3ENR_CRYPEN)
    #endif
    #ifdef RCC_AHB3ENR_SAESEN
        #define WC_STM32_SAES_CLK_ENABLE() \
            WC_STM32_CLK_EN(AHB3ENR, RCC_AHB3ENR_SAESEN)
        #define WC_STM32_SAES_CLK_DISABLE() \
            WC_STM32_CLK_DIS(AHB3ENR, RCC_AHB3ENR_SAESEN)
    #endif
    #define WC_STM32_HASH_CLK_ENABLE() \
        WC_STM32_CLK_EN(AHB3ENR, RCC_AHB3ENR_HASHEN)
    #define WC_STM32_HASH_CLK_DISABLE() \
        WC_STM32_CLK_DIS(AHB3ENR, RCC_AHB3ENR_HASHEN)
    #define WC_STM32_RNG_CLK_ENABLE() \
        WC_STM32_CLK_EN(AHB3ENR, RCC_AHB3ENR_RNGEN)
#endif

/* Build-time AES IP instance selector. Default is the regular AES/CRYP
 * peripheral; defining WOLFSSL_STM32_USE_SAES routes the BARE TinyAES
 * register-access block to SAES (Secure AES) instead. The TinyAES
 * register layout is identical for AES and SAES on H5/U5/WBA/C5. */
#ifndef WC_STM32_AES_INST
    #if defined(WOLFSSL_STM32_USE_SAES) && defined(SAES)
        #define WC_STM32_AES_INST  SAES
    #elif defined(CRYP)
        #define WC_STM32_AES_INST  CRYP
    #elif defined(AES)
        /* AES-only chips (G0/L0/U0) -- no fat CRYP, no SAES. The
         * symbol CRYP is the legacy alias many newer family headers
         * keep for compatibility, but bottom-end chips drop it. */
        #define WC_STM32_AES_INST  AES
    #elif defined(WOLFSSL_STM32WB) && defined(AES1)
        /* WB55 dual-core: CMSIS exposes AES1 (M4-side application AES)
         * and AES2 (M0+ Cortex-M0+ radio-side, not addressable from
         * the application core). There is no plain `AES` or `CRYP`
         * alias in the device header, so pick AES1 directly. */
        #define WC_STM32_AES_INST  AES1
    #elif defined(STM32_CRYPTO)
        /* Only error when the board has actually asked for STM32_CRYPTO
         * but no AES IP is reachable. Chips with NO_STM32_CRYPTO (e.g.
         * F767/G491/F767 -- RNG-only parts) don't need an instance. */
        #error "STM32 BARE: no AES/CRYP/SAES instance pointer found"
    #endif
#endif

/* Companion macro for the IP-instance clock enable. Routes to
 * WC_STM32_SAES_CLK_ENABLE when WOLFSSL_STM32_USE_SAES is set and the
 * family arm above provided the SAES variant; otherwise falls back to
 * the regular AES clock. The two are separate AHB enable bits on
 * H5/U5/WBA/C5, so toggling the wrong one leaves the IP disabled. */
#ifndef WC_STM32_AES_CLK_ENABLE_INST
    #if defined(WOLFSSL_STM32_USE_SAES) && defined(WC_STM32_SAES_CLK_ENABLE)
        #define WC_STM32_AES_CLK_ENABLE_INST()  WC_STM32_SAES_CLK_ENABLE()
    #else
        #define WC_STM32_AES_CLK_ENABLE_INST()  WC_STM32_AES_CLK_ENABLE()
    #endif
#endif

/* Some new-gen chips (STM32N6, STM32H7S3) ship CMSIS headers that
 * define SAES_TypeDef but not AES_TypeDef. The BARE TinyAES driver
 * helpers in stm32.c declare their parameter as `AES_TypeDef*` so the
 * same function pointer can target both the regular AES and SAES
 * instances on chips that have both. Provide a typedef alias when AES
 * is missing -- the IP layout is identical between AES and SAES on
 * every family in scope. Gated on having SAES but not the AES_CR_EN
 * symbol (used as a sentinel that the CMSIS lacks the AES alias). */
#if defined(SAES) && !defined(AES_CR_EN) && \
    !defined(WOLFSSL_STM32_AES_TYPEDEF_ALIAS)
    typedef SAES_TypeDef AES_TypeDef;
    #define WOLFSSL_STM32_AES_TYPEDEF_ALIAS
#endif

/* SAES-only chips (e.g. STM32N6) have the TinyAES register layout but
 * the CMSIS device header only defines SAES_CR_*, SAES_SR_*, SAES_ISR_*,
 * SAES_ICR_* without companion AES_CR_* aliases. The BARE driver in
 * stm32.c uses the AES_CR_* names directly; provide aliases here so the
 * existing code compiles on SAES-only parts. */
#if !defined(AES_CR_EN) && defined(SAES_CR_EN)
    #define AES_CR_EN          SAES_CR_EN
    #define AES_CR_DATATYPE_1  SAES_CR_DATATYPE_1
    #define AES_CR_MODE        SAES_CR_MODE
    #define AES_CR_MODE_M      SAES_CR_MODE_Msk
    #define AES_CR_MODE_Msk    SAES_CR_MODE_Msk
    #define AES_CR_MODE_0      SAES_CR_MODE_0
    #define AES_CR_MODE_1      SAES_CR_MODE_1
    #define AES_CR_CHMOD_0     SAES_CR_CHMOD_0
    #define AES_CR_CHMOD_1     SAES_CR_CHMOD_1
    #define AES_CR_KEYSIZE     SAES_CR_KEYSIZE
    #define AES_CR_KEYSEL_0    SAES_CR_KEYSEL_0
    #define AES_CR_KMOD_0      SAES_CR_KMOD_0
    #define AES_CR_KEYPROT     SAES_CR_KEYPROT
    #define AES_CR_CCFC        SAES_CR_CCFC
    #define AES_CR_IPRST       SAES_CR_IPRST
    #define AES_SR_BUSY        SAES_SR_BUSY
    #define AES_SR_CCF         SAES_SR_CCF
    #define AES_ISR_CCF        SAES_ISR_CCF
    #define AES_ICR_CCF        SAES_ICR_CCF
#endif

/* Per-family direct-register clock-enable macro for the PKA peripheral. */
#if defined(WOLFSSL_STM32WB) || defined(WOLFSSL_STM32WL)
    /* WB55 / WL55: PKA clock is on AHB3 (V1 layout) */
    #define WC_STM32_PKA_CLK_ENABLE() \
        do { RCC->AHB3ENR |= RCC_AHB3ENR_PKAEN; (void)RCC->AHB3ENR; } while (0)
#elif defined(WOLFSSL_STM32U5) || defined(WOLFSSL_STM32U3)
    /* U5 / U3: AHB2ENR1.PKAEN */
    #ifdef RCC_AHB2ENR1_PKAEN
        #define WC_STM32_PKA_CLK_ENABLE() \
            do { RCC->AHB2ENR1 |= RCC_AHB2ENR1_PKAEN; (void)RCC->AHB2ENR1; } \
                while (0)
    #endif
#elif defined(WOLFSSL_STM32H5)
    #ifdef RCC_AHB2ENR_PKAEN
        #define WC_STM32_PKA_CLK_ENABLE() \
            do { RCC->AHB2ENR |= RCC_AHB2ENR_PKAEN; (void)RCC->AHB2ENR; } \
                while (0)
    #endif
#elif defined(WOLFSSL_STM32L5)
    /* L5: PKA on AHB2ENR.PKAEN (bit 19). Only present on L562/L592
     * variants -- L552 has no PKA so the CMSIS bit is absent. */
    #ifdef RCC_AHB2ENR_PKAEN
        #define WC_STM32_PKA_CLK_ENABLE() \
            do { RCC->AHB2ENR |= RCC_AHB2ENR_PKAEN; (void)RCC->AHB2ENR; } \
                while (0)
    #endif
#elif defined(WOLFSSL_STM32G4)
    #ifdef RCC_AHB2ENR_PKAEN
        #define WC_STM32_PKA_CLK_ENABLE() \
            do { RCC->AHB2ENR |= RCC_AHB2ENR_PKAEN; (void)RCC->AHB2ENR; } \
                while (0)
    #endif
#elif defined(WOLFSSL_STM32WBA)
    /* WBA52: PKA on AHB2ENR.PKAEN bit 21 (NOT AHB1 like the rest of
     * the WBA crypto IPs in some other variants -- the WBA52 RM places
     * PKA, SAES, RNG all on AHB2 alongside other crypto). The earlier
     * AHB1 placement was a copy-paste error from another family;
     * `RCC_AHB1ENR_PKAEN` doesn't exist on WBA52 so the macro never
     * defined, the clock never got enabled, and HAL_PKA_Init timed
     * out at the CR.EN-stick check (CR readback = 0 = clock gated). */
    #ifdef RCC_AHB2ENR_PKAEN
        #define WC_STM32_PKA_CLK_ENABLE() \
            do { RCC->AHB2ENR |= RCC_AHB2ENR_PKAEN; (void)RCC->AHB2ENR; } \
                while (0)
    #endif
#elif defined(WOLFSSL_STM32C5)
    #ifdef RCC_AHB2ENR_PKAEN
        #define WC_STM32_PKA_CLK_ENABLE() \
            do { RCC->AHB2ENR |= RCC_AHB2ENR_PKAEN; (void)RCC->AHB2ENR; } \
                while (0)
    #endif
#elif defined(WOLFSSL_STM32N6)
    /* N6: PKA on AHB3 (same bank as HASH/RNG/CRYP/SAES). V2 layout. */
    #ifdef RCC_AHB3ENR_PKAEN
        #define WC_STM32_PKA_CLK_ENABLE() \
            do { RCC->AHB3ENR |= RCC_AHB3ENR_PKAEN; (void)RCC->AHB3ENR; } \
                while (0)
    #endif
#elif defined(WOLFSSL_STM32H7S)
    /* H7S: PKA on AHB3 alongside HASH/RNG/CRYP/SAES. V2 layout. */
    #ifdef RCC_AHB3ENR_PKAEN
        #define WC_STM32_PKA_CLK_ENABLE() \
            do { RCC->AHB3ENR |= RCC_AHB3ENR_PKAEN; (void)RCC->AHB3ENR; } \
                while (0)
    #endif
#endif

/* HAL-legacy macros that the existing direct-register HASH path depends on.
 * Without HAL these aren't otherwise visible. */
#if defined(WOLFSSL_STM32H5) || defined(WOLFSSL_STM32MP13) || \
    defined(WOLFSSL_STM32N6) || defined(WOLFSSL_STM32H7S) || \
    defined(WOLFSSL_STM32U3) || defined(WOLFSSL_STM32C5)
    /* New-generation HASH IP. The CMSIS struct shape varies within the
     * family list -- H5 renames the instance digest registers from
     * `HR[5]` to `HRA[5]`, but U3 / N6 keep the legacy `HR[5]` name
     * even though the IP otherwise behaves like the new generation.
     * Gate the macro on H5 only (verified by inspection of each
     * family's CMSIS header). */
    #if defined(WOLFSSL_STM32H5)
        #define WC_STM32_HASH_INSTANCE_HRA
    #endif
    /* 4-bit ALGO field at bits 20:17 */
    #define HASH_ALGOSELECTION_SHA1       0u
    #define HASH_ALGOSELECTION_SHA224     HASH_CR_ALGO_1
    #define HASH_ALGOSELECTION_SHA256     (HASH_CR_ALGO_0 | HASH_CR_ALGO_1)
    #define HASH_ALGOSELECTION_SHA384     (HASH_CR_ALGO_2 | HASH_CR_ALGO_3)
    #define HASH_ALGOSELECTION_SHA512     (HASH_CR_ALGO_0 | HASH_CR_ALGO_1 | \
                                           HASH_CR_ALGO_2 | HASH_CR_ALGO_3)
    #define HASH_ALGOSELECTION_SHA512_224 (HASH_CR_ALGO_0 | HASH_CR_ALGO_2 | \
                                           HASH_CR_ALGO_3)
    #define HASH_ALGOSELECTION_SHA512_256 (HASH_CR_ALGO_1 | HASH_CR_ALGO_2 | \
                                           HASH_CR_ALGO_3)
#else
    /* Older HASH IP (F4/F7/L4 family) ALGO bit mapping (per HAL):
     *   SHA1   = 0
     *   MD5    = ALGO_0
     *   SHA224 = ALGO_1
     *   SHA256 = ALGO_0 | ALGO_1
     */
    #define HASH_ALGOSELECTION_SHA1       0u
    #define HASH_ALGOSELECTION_MD5        HASH_CR_ALGO_0
    #ifdef HASH_CR_ALGO_1
        #define HASH_ALGOSELECTION_SHA224 HASH_CR_ALGO_1
        #define HASH_ALGOSELECTION_SHA256 (HASH_CR_ALGO_0 | HASH_CR_ALGO_1)
    #endif
#endif

/* Legacy CamelCase aliases */
#ifdef HASH_ALGOSELECTION_SHA1
    #define HASH_AlgoSelection_SHA1       HASH_ALGOSELECTION_SHA1
#endif
#ifdef HASH_ALGOSELECTION_SHA224
    #define HASH_AlgoSelection_SHA224     HASH_ALGOSELECTION_SHA224
#endif
#ifdef HASH_ALGOSELECTION_SHA256
    #define HASH_AlgoSelection_SHA256     HASH_ALGOSELECTION_SHA256
#endif
#ifdef HASH_ALGOSELECTION_SHA384
    #define HASH_AlgoSelection_SHA384     HASH_ALGOSELECTION_SHA384
#endif
#ifdef HASH_ALGOSELECTION_SHA512
    #define HASH_AlgoSelection_SHA512     HASH_ALGOSELECTION_SHA512
#endif
#ifdef HASH_ALGOSELECTION_SHA512_224
    #define HASH_AlgoSelection_SHA512_224 HASH_ALGOSELECTION_SHA512_224
#endif
#ifdef HASH_ALGOSELECTION_SHA512_256
    #define HASH_AlgoSelection_SHA512_256 HASH_ALGOSELECTION_SHA512_256
#endif
#ifdef HASH_ALGOSELECTION_MD5
    #define HASH_AlgoSelection_MD5        HASH_ALGOSELECTION_MD5
#endif

#define HASH_ALGOMODE_HASH              0u
#ifdef HASH_CR_MODE
    #define HASH_ALGOMODE_HMAC          HASH_CR_MODE
#endif
/* Byte-stream input (auto byte-swap) */
#ifdef HASH_CR_DATATYPE_1
    #define HASH_DATATYPE_8B            HASH_CR_DATATYPE_1
#elif defined(HASH_CR_DATATYPE_0)
    #define HASH_DATATYPE_8B            HASH_CR_DATATYPE_0
#endif

#endif /* WOLFSSL_STM32_BARE */


#ifdef STM32_HASH

#include <stdint.h> /* for uint32_t */

#define WOLFSSL_NO_HASH_RAW

#ifdef HASH_DIGEST
    /* The HASH_DIGEST register indicates SHA224/SHA256 support */
    #define STM32_HASH_SHA2
    #if defined(WOLFSSL_STM32MP13) || defined(WOLFSSL_STM32H7S) || \
        defined(WOLFSSL_STM32N6) || defined(WOLFSSL_STM32H5) || \
        defined(WOLFSSL_STM32U3)
        #define HASH_CR_SIZE    103
        #define HASH_MAX_DIGEST 64 /* Up to SHA512 */

        #define STM32_HASH_SHA512
        #define STM32_HASH_SHA512_224
        #define STM32_HASH_SHA512_256
        #define STM32_HASH_SHA384
    #else
        #define HASH_CR_SIZE    54
        #define HASH_MAX_DIGEST 32
    #endif
    #if defined(WOLFSSL_STM32MP13)
        #define STM32_HASH_SHA3
    #endif
#else
    #define HASH_CR_SIZE    50
    #define HASH_MAX_DIGEST 20
#endif

#ifdef WOLFSSL_STM32MP13
    /* From stm32_hal_legacy.h, but that MP13 header has a bug in it */
    #define HASH_AlgoSelection_MD5       HASH_ALGOSELECTION_MD5
    #define HASH_AlgoSelection_SHA1      HASH_ALGOSELECTION_SHA1
    #define HASH_AlgoSelection_SHA224    HASH_ALGOSELECTION_SHA224
    #define HASH_AlgoSelection_SHA256    HASH_ALGOSELECTION_SHA256
#endif

/* These HASH HAL's have no MD5 implementation */
#if defined(WOLFSSL_STM32MP13) || defined(WOLFSSL_STM32H7S) || \
    defined(WOLFSSL_STM32N6) || defined(WOLFSSL_STM32H5) || \
    defined(WOLFSSL_STM32U3) || defined(WOLFSSL_STM32C5)
    #define STM32_NOMD5
#endif

/* Handle hash differences between CubeMX and StdPeriLib */
#if !defined(HASH_ALGOMODE_HASH) && defined(HASH_AlgoMode_HASH)
    #define HASH_ALGOMODE_HASH HASH_AlgoMode_HASH
#endif
#if !defined(HASH_ALGOMODE_HMAC) && defined(HASH_AlgoMode_HMAC)
    #define HASH_ALGOMODE_HMAC HASH_AlgoMode_HMAC
#endif
#if !defined(HASH_DATATYPE_8B)
    #if defined(HASH_DataType_8b)
        #define HASH_DATATYPE_8B HASH_DataType_8b
    #elif defined(HASH_BYTE_SWAP)
        #define HASH_DATATYPE_8B HASH_BYTE_SWAP
    #endif
#endif
#ifndef HASH_STR_NBW
    #define HASH_STR_NBW HASH_STR_NBLW
#endif

#ifndef STM32_HASH_TIMEOUT
    #define STM32_HASH_TIMEOUT 0xFFFF
#endif


/* STM32 register size in bytes */
#define STM32_HASH_REG_SIZE  4
/* Maximum FIFO buffer is 64 bits for SHA256, 128 bits for SHA512 and 144 bits
 * for SHA3 */
#if defined(STM32_HASH_SHA3)
    #define STM32_HASH_FIFO_SIZE 36
#elif defined(STM32_HASH_SHA512) || defined(STM32_HASH_SHA384)
    #define STM32_HASH_FIFO_SIZE 32
#else
    #define STM32_HASH_FIFO_SIZE 16
#endif

/* STM32 Hash Context */
typedef struct {
    /* Context switching registers */
    uint32_t HASH_IMR;
    uint32_t HASH_STR;
    uint32_t HASH_CR;
    uint32_t HASH_CSR[HASH_CR_SIZE];
#ifdef STM32_HASH_SHA3
    uint32_t SHA3CFGR;
#endif

    /* Hash state / buffers */
    word32 buffer[STM32_HASH_FIFO_SIZE+1]; /* partial word buffer */
    word32 buffLen; /* partial word remain */
    word32 loLen;   /* total update bytes
                 (only lsb 6-bits is used for nbr valid bytes in last word) */
    word32 fifoBytes; /* number of currently filled FIFO bytes */
} STM32_HASH_Context;


/* API's */
void wc_Stm32_Hash_Init(STM32_HASH_Context* stmCtx);
int  wc_Stm32_Hash_Update(STM32_HASH_Context* stmCtx, word32 algo,
    const byte* data, word32 len, word32 blockSize);
int  wc_Stm32_Hash_Final(STM32_HASH_Context* stmCtx, word32 algo,
    byte* hash, word32 digestSize);

#ifdef STM32_HMAC
/* STM32 Hardware HMAC API */
int wc_Stm32_Hmac_GetAlgoInfo(int macType, word32* algo, word32* blockSize,
    word32* digestSize);
int wc_Stm32_Hmac_SetKey(STM32_HASH_Context* stmCtx, int macType,
    const byte* key, word32 keySz);
/* HMAC Update uses the same data feeding as Hash Update */
#define wc_Stm32_Hmac_Update(stmCtx, algo, data, len, blockSize) \
    wc_Stm32_Hash_Update((stmCtx), (algo), (data), (len), (blockSize))
int wc_Stm32_Hmac_Final(STM32_HASH_Context* stmCtx, word32 algo,
    const byte* key, word32 keySz, byte* hash, word32 digestSize);
#endif /* STM32_HMAC */

#endif /* STM32_HASH */


#ifdef STM32_CRYPTO

#if defined(WOLFSSL_STM32MP13)
    #define RNG RNG1
    #define CRYP CRYP1
    #define hcryp hcryp1
    #define FORMAT_BIN RTC_FORMAT_BIN
    #define __HAL_RCC_RNG_CLK_ENABLE __HAL_RCC_RNG1_CLK_ENABLE
    #define __HAL_RCC_HASH_CLK_ENABLE __HAL_RCC_HASH1_CLK_ENABLE
    #define __HAL_RCC_HASH_CLK_DISABLE __HAL_RCC_HASH1_CLK_DISABLE
#endif

#ifndef NO_AES
    #if !defined(STM32_CRYPTO_AES_GCM) && !defined(WOLFSSL_STM32_BARE) && \
            (defined(WOLFSSL_STM32F4) || \
            defined(WOLFSSL_STM32F7) || defined(WOLFSSL_STM32L4) || \
            defined(WOLFSSL_STM32L5) || defined(WOLFSSL_STM32H7) || \
            defined(WOLFSSL_STM32U5) || defined(WOLFSSL_STM32U3) || \
            defined(WOLFSSL_STM32H5) || defined(WOLFSSL_STM32MP13) || \
            defined(WOLFSSL_STM32H7S) || defined(WOLFSSL_STM32N6) || \
            defined(WOLFSSL_STM32G0))
        /* Hardware supports AES GCM acceleration */
        #define STM32_CRYPTO_AES_GCM
    #endif
    /* Under WOLFSSL_STM32_BARE on the CRYP IP (F2/F4/F7/H7/MP13), the GCM
     * HW phase machine (init/header/payload/final) is engaged for whole-
     * block PT with a 12-byte IV; partial blocks and non-12B IVs return
     * CRYPTOCB_UNAVAILABLE so aes.c falls back to SW GHASH + HW ECB. On
     * the TinyAES IP the BARE driver always returns CRYPTOCB_UNAVAILABLE
     * for GCM (no HW phase machine) and the SW GHASH + HW ECB path is
     * used. GCM decrypt is always SW + HW ECB on both IPs in v1. */

    #if defined(WOLFSSL_STM32WB) || defined(WOLFSSL_STM32WL) || \
        defined(WOLFSSL_STM32WBA)
        #define STM32_CRYPTO_AES_ONLY /* crypto engine only supports AES */
        #ifdef WOLFSSL_STM32WB
            #define CRYP AES1
        #else
            #define CRYP AES
        #endif
        #define STM32_HAL_V2
    #endif
    #if defined(WOLFSSL_STM32L4) || defined(WOLFSSL_STM32L5) || \
        defined(WOLFSSL_STM32U5) || defined(WOLFSSL_STM32U3) || \
        defined(WOLFSSL_STM32H5) || defined(WOLFSSL_STM32G0) || \
        defined(WOLFSSL_STM32G4) || defined(WOLFSSL_STM32C5)
        #if defined(WOLFSSL_STM32L4) || defined(WOLFSSL_STM32U5) || \
            defined(WOLFSSL_STM32U3) || defined(WOLFSSL_STM32G0) || \
            defined(WOLFSSL_STM32G4) || defined(WOLFSSL_STM32C5)
            #define STM32_CRYPTO_AES_ONLY /* crypto engine only supports AES */
        #endif
        #if defined(WOLFSSL_STM32H5) || defined(WOLFSSL_STM32C5)
            #define __HAL_RCC_CRYP_CLK_DISABLE  __HAL_RCC_AES_CLK_DISABLE
            #define __HAL_RCC_CRYP_CLK_ENABLE   __HAL_RCC_AES_CLK_ENABLE
        #endif
        #define CRYP AES
        #ifndef CRYP_AES_GCM
            #define CRYP_AES_GCM CRYP_AES_GCM_GMAC
        #endif
    #endif

    /* Detect newer CubeMX crypto HAL (HAL_CRYP_Encrypt / HAL_CRYP_Decrypt) */
    #if !defined(STM32_HAL_V2) && defined(CRYP_AES_GCM) && \
        (defined(WOLFSSL_STM32F7) || defined(WOLFSSL_STM32L5) || \
         defined(WOLFSSL_STM32H7) || defined(WOLFSSL_STM32U5) || \
         defined(WOLFSSL_STM32U3) || defined(WOLFSSL_STM32H5) || \
         defined(WOLFSSL_STM32MP13) || defined(WOLFSSL_STM32H7S) || \
         defined(WOLFSSL_STM32N6) || defined(WOLFSSL_STM32G0))
        #define STM32_HAL_V2
    #endif

    /* The datatype for STM32 CubeMX HAL Crypt calls */
    #ifdef STM32_HAL_V2
        #define STM_CRYPT_TYPE uint32_t
    #else
        #define STM_CRYPT_TYPE uint8_t
    #endif

    /* Determine minimum AES GCM alignment supported */
    #ifndef STM_CRYPT_HEADER_WIDTH
        /* newer crypt HAL requires auth header size as 4 bytes (word) */
        #if defined(CRYP_HEADERWIDTHUNIT_BYTE) && \
            !defined(WOLFSSL_STM32MP13) && !defined(WOLFSSL_STM32H7S) && \
            !defined(WOLFSSL_STM32N6)
            #define STM_CRYPT_HEADER_WIDTH 1
        #else
            #define STM_CRYPT_HEADER_WIDTH 4
        #endif
    #endif

    /* CRYPT_AES_GCM starts the IV with 2 */
    #define STM32_GCM_IV_START 2

    struct Aes;
    #ifdef WOLFSSL_STM32_BARE
        /* Bare-metal direct-register AES driver. ECB and CBC are HW-native;
         * CTR is provided automatically via the ECB-as-transform path in
         * aes.c (XTRANSFORM_AESCTRBLOCK); GCM is HW-native for the case
         * the CRYP IP supports (12-byte IV + whole-block PT) and returns
         * CRYPTOCB_UNAVAILABLE otherwise so aes.c can fall back to SW
         * GHASH (which still uses HW ECB for the underlying AES blocks). */
        int wc_Stm32_Aes_Ecb(struct Aes* aes, byte* out, const byte* in,
                word32 sz, int isEnc);
        int wc_Stm32_Aes_Cbc(struct Aes* aes, byte* out, const byte* in,
                word32 sz, int isEnc);
        int wc_Stm32_Aes_Gcm(struct Aes* aes, byte* out, const byte* in,
                word32 sz,
                const byte* iv, word32 ivSz,
                byte* tag, word32 tagSz,
                const byte* aad, word32 aadSz, int isEnc);
    #elif defined(WOLFSSL_STM32_CUBEMX)
        int wc_Stm32_Aes_Init(struct Aes* aes, CRYP_HandleTypeDef* hcryp,
                int useSAES);
        void wc_Stm32_Aes_Cleanup(void);
    #else /* Standard Peripheral Library */
        int wc_Stm32_Aes_Init(struct Aes* aes, CRYP_InitTypeDef* cryptInit,
            CRYP_KeyInitTypeDef* keyInit);
        void wc_Stm32_Aes_Cleanup(void);
    #endif /* WOLFSSL_STM32_BARE / WOLFSSL_STM32_CUBEMX / StdPeriph */
#endif /* !NO_AES */

#endif /* STM32_CRYPTO */

/* DHUK (Device Hardware Unique Key) -- SAES key wrap / unwrap using a
 * silicon-bound key. Originally introduced for STM32U5 only; the
 * underlying SAES + DHUK infrastructure is also present on U3, H5,
 * WBA, and C5. Use WOLFSSL_DHUK going forward; WOLFSSL_STM32U5_DHUK
 * is kept as a backwards-compatible alias for one release cycle. */
#if defined(WOLFSSL_STM32U5_DHUK) && !defined(WOLFSSL_DHUK)
    #define WOLFSSL_DHUK
#endif
#if defined(WOLFSSL_DHUK) && !defined(WOLFSSL_STM32U5_DHUK)
    #define WOLFSSL_STM32U5_DHUK
#endif

/* Family gate: only families that actually have SAES + DHUK silicon.
 * L5 has a "secure AES" instance but its CR layout does not include
 * KMOD / KEYSEL fields -- it does not implement the same DHUK key-
 * wrap protocol as U5/U3/H5/WBA/C5. L5 is intentionally excluded. */
#if defined(WOLFSSL_DHUK) && \
    (defined(WOLFSSL_STM32U5) || defined(WOLFSSL_STM32U3) || \
     defined(WOLFSSL_STM32H5) || defined(WOLFSSL_STM32WBA) || \
     defined(WOLFSSL_STM32C5) || defined(WOLFSSL_STM32H7S))
    #define WC_STM32_HAS_DHUK
#endif

/* Transparent DHUK crypto flows through the crypto-callback framework, so
 * WOLF_CRYPTO_CB is mandatory whenever DHUK is enabled. */
#if defined(WOLFSSL_DHUK) && !defined(WOLF_CRYPTO_CB)
    #error "WOLFSSL_DHUK requires WOLF_CRYPTO_CB (crypto callback dispatch)"
#endif

#if defined(WOLFSSL_DHUK) && !defined(WOLFSSL_DHUK_DEVID)
    /* SAES / DHUK device IDs. wc_Stm32_Aes_Wrap selects the wrap-key source
     * by aes->devId (HW DHUK vs a software key). Transparent DHUK crypto
     * routes through the crypto-callback device registered at WC_DHUK_DEVID
     * (see wc_Stm32_DhukRegister), not these markers. */
    #define WOLFSSL_DHUK_DEVID              808
    #define WOLFSSL_SAES_DEVID              807
    /* Crypto-callback device id for transparent DHUK crypto (same value as the
     * SAES/DHUK marker; override before include if it collides). */
    #ifndef WC_DHUK_DEVID
        #define WC_DHUK_DEVID              808
    #endif

    int wc_Stm32_Aes_Wrap(struct Aes* aes, const byte* in, word32 inSz, byte* out,
        word32* outSz, const byte* iv, int ivSz);
#ifdef WOLFSSL_STM32_BARE
    /* Optional exact-key import primitive: unwrap a DHUK-wrapped key into SAES
     * KEYR and ECB/CBC with it. _ex `isCbc`: 0=ECB, 1=CBC. Returns
     * CRYPTOCB_UNAVAILABLE unless built with WOLFSSL_STM32_DHUK_UNWRAP. Not
     * auto-routed -- call explicitly (DHUK uses the cryptocb path). */
    int wc_Stm32_Aes_DhukOp(struct Aes* aes, byte* out, const byte* in,
        word32 sz, int isEnc);
    int wc_Stm32_Aes_DhukOp_ex(struct Aes* aes, byte* out, const byte* in,
        word32 sz, int isEnc, int isCbc);
#endif
#endif

#if defined(WOLFSSL_STM32_PKA) && defined(HAVE_ECC)
struct ecc_key;
struct WC_RNG;

int stm32_ecc_verify_hash_ex(MATH_INT_T *r, MATH_INT_T *s, const byte* hash,
                    word32 hashlen, int* res, struct ecc_key* key);

int stm32_ecc_sign_hash_ex(const byte* hash, word32 hashlen, struct WC_RNG* rng,
                     struct ecc_key* key, MATH_INT_T *r, MATH_INT_T *s);
#endif /* WOLFSSL_STM32_PKA && HAVE_ECC */


/* DHUK BARE port: the STM32 crypto-callback device. Built on families with
 * SAES + DHUK (the WC_STM32_HAS_DHUK gate); transparent DHUK crypto (AES /
 * GMAC / ECDSA) routes through it via the cryptocb path. */
#if defined(WOLFSSL_STM32_BARE) && defined(WC_STM32_HAS_DHUK)

#ifdef WOLF_CRYPTO_CB
    /* Register / unregister the STM32 DHUK device. After registering at
     * WC_DHUK_DEVID, set an object's devId to it at init
     * (wc_AesInit / wc_ecc_init_ex) and supply the 256-bit seed as the key
     * (wc_AesGcmSetKey) or via wc_ecc_import_wrapped_private(). */
    int  wc_Stm32_DhukRegister(int devId);
    void wc_Stm32_DhukUnRegister(int devId);
#endif

#endif /* WOLFSSL_STM32_BARE && WC_STM32_HAS_DHUK */


#endif /* _WOLFPORT_STM32_H_ */
