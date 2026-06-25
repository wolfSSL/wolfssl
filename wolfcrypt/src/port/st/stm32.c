/* stm32.c
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

/* Generic STM32 Hashing Function */
/* Supports CubeMX HAL or Standard Peripheral Library */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/wolfcrypt/port/st/stm32.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#ifdef WOLFSSL_DHUK
    #include <wolfssl/wolfcrypt/cryptocb.h>
    #ifdef HAVE_ECC
        #include <wolfssl/wolfcrypt/ecc.h>
    #endif
#endif

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#ifndef NO_AES
    #include <wolfssl/wolfcrypt/aes.h>
#endif

#ifdef WOLFSSL_STM32_PKA
#include <stdint.h>

#ifdef WOLFSSL_STM32_BARE
/* Bare-metal: CMSIS device header comes from settings.h; the
 * PKA_HandleTypeDef and PKA IO typedefs come from port/st/stm32.h. The
 * HAL_PKA_* entry points are implemented further down under the matching
 * guard.
 *
 * BARE debug switches (off by default, opt-in at -D; no code unless set):
 *   WC_STM32_PKA_DIAG   -- printf on PKA init / op timeout / OUT_ERROR.
 *   WC_STM32_SAES_DIAG  -- printf on AES/SAES CCF poll timeout
 *                          (DEBUG_STM32_BARE_GCM is a synonym). */
#else
#if defined(WOLFSSL_STM32L5)
#include <stm32l5xx_hal_conf.h>
#include <stm32l5xx_hal_pka.h>
#elif defined(WOLFSSL_STM32U5)
#include <stm32u5xx_hal_conf.h>
#include <stm32u5xx_hal_pka.h>
#elif defined(WOLFSSL_STM32WB)
#include <stm32wbxx_hal_conf.h>
#include <stm32wbxx_hal_pka.h>
#elif defined(WOLFSSL_STM32WL)
#include <stm32wlxx_hal_conf.h>
#include <stm32wlxx_hal_pka.h>
#elif defined(WOLFSSL_STM32MP13)
#include <stm32mp13xx_hal_conf.h>
#include <stm32mp13xx_hal_pka.h>
#elif defined(WOLFSSL_STM32H7S)
#include <stm32h7rsxx_hal_conf.h>
#include <stm32h7rsxx_hal_pka.h>
#elif defined(WOLFSSL_STM32WBA)
#include <stm32wbaxx_hal_conf.h>
#include <stm32wbaxx_hal_pka.h>
#elif defined(WOLFSSL_STM32N6)
#include <stm32n6xx_hal_conf.h>
#include <stm32n6xx_hal_pka.h>
#elif defined(WOLFSSL_STM32H5)
#include <stm32h5xx_hal_conf.h>
#include <stm32h5xx_hal_pka.h>
#else
#error Please add the hal_pk.h include
#endif
#endif /* !WOLFSSL_STM32_BARE */

#if defined(WOLFSSL_STM32_BARE) && defined(WOLFSSL_STM32_PKA)

#include <stdint.h>

/* Bare-metal stand-ins for the slice of HAL surface that wc_ecc_*() and
 * the local HAL_PKA_* shims reference. Kept private to this translation
 * unit so they don't collide with ST HAL headers in projects that include
 * those for non-crypto code. */
typedef enum {
    HAL_OK      = 0x00U,
    HAL_ERROR   = 0x01U,
    HAL_BUSY    = 0x02U,
    HAL_TIMEOUT = 0x03U
} HAL_StatusTypeDef;

#ifndef HAL_MAX_DELAY
#define HAL_MAX_DELAY 0xFFFFFFFFU
#endif

typedef struct {
    PKA_TypeDef *Instance;
    /* V2 PKA clobbers RAM[PKA_ECDSA_SIGN_IN_MOD_NB_BITS] during the
     * sign operation -- it cannot be read back to determine the
     * result size. Mirror the HAL handle and save the modulus size
     * (in bytes) at sign-setup time so GetResult can use it. V1 HAL
     * reads from RAM and works fine; V2 HAL keeps it on the handle. */
    uint32_t primeordersize;
} PKA_HandleTypeDef;

typedef struct {
    uint32_t       modulusSize;
    uint32_t       coefSign;
    const uint8_t *coefA;
    const uint8_t *coefB;       /* V2 only */
    const uint8_t *modulus;
    const uint8_t *primeOrder;  /* V2 only */
    uint32_t       scalarMulSize;
    const uint8_t *scalarMul;
    const uint8_t *pointX;
    const uint8_t *pointY;
} PKA_ECCMulInTypeDef;

typedef struct {
    uint8_t *ptX;
    uint8_t *ptY;
} PKA_ECCMulOutTypeDef;

typedef struct {
    uint32_t       primeOrderSize;
    uint32_t       modulusSize;
    uint32_t       coefSign;
    const uint8_t *coef;
    const uint8_t *coefB;       /* V2 only */
    const uint8_t *modulus;
    const uint8_t *basePointX;
    const uint8_t *basePointY;
    const uint8_t *primeOrder;
    const uint8_t *pPubKeyCurvePtX;
    const uint8_t *pPubKeyCurvePtY;
    const uint8_t *RSign;
    const uint8_t *SSign;
    const uint8_t *hash;
} PKA_ECDSAVerifInTypeDef;

typedef struct {
    uint32_t       primeOrderSize;
    uint32_t       modulusSize;
    uint32_t       coefSign;
    const uint8_t *coef;
    const uint8_t *coefB;       /* V2 only */
    const uint8_t *modulus;
    const uint8_t *basePointX;
    const uint8_t *basePointY;
    const uint8_t *primeOrder;
    const uint8_t *hash;
    const uint8_t *integer;
    const uint8_t *privateKey;
} PKA_ECDSASignInTypeDef;

typedef struct {
    uint8_t *RSign;
    uint8_t *SSign;
} PKA_ECDSASignOutTypeDef;

typedef struct {
    uint8_t *ptX;
    uint8_t *ptY;
} PKA_ECDSASignOutExtParamTypeDef;

#endif /* WOLFSSL_STM32_BARE && WOLFSSL_STM32_PKA */

#ifdef WOLFSSL_STM32_BARE
/* Provide the global PKA handle that the wc_ecc_mulmod_ex2() and
 * stm32_ecc_*_hash_ex() paths reference via &hpka. Under HAL builds,
 * the application supplies this; under BARE we own it (file-local). */
static PKA_HandleTypeDef hpka = { 0 };
#else
extern PKA_HandleTypeDef hpka;
#endif

#if !defined(WOLFSSL_STM32_PKA_V2) && defined(PKA_ECC_SCALAR_MUL_IN_B_COEFF)
/* PKA hardware like in U5 added coefB and primeOrder */
#define WOLFSSL_STM32_PKA_V2
#endif

#ifdef HAVE_ECC
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/asn.h>

#ifndef WOLFSSL_HAVE_ECC_KEY_GET_PRIV
    /* FIPS build has replaced ecc.h. */
    #define wc_ecc_key_get_priv(key) (&((key)->k))
    #define WOLFSSL_HAVE_ECC_KEY_GET_PRIV
#endif
#endif /* HAVE_ECC */

/* Bare-metal HAL_PKA_* shims -- direct-register slice of ST HAL surface
 * used by the wolfssl PKA path. V1 layout (WB55/WL/MP13); V2 PKA (H5/
 * U5+PKA/WBA) adds coefB / primeOrder / pointCheck slots at different
 * offsets but shares the start sequence and SR/CLRFR bit names, so the
 * V2 differences fold into the same code path under WOLFSSL_STM32_PKA_V2
 * (auto-set when the CMSIS header defines PKA_ECC_SCALAR_MUL_IN_B_COEFF).
 * Reference: STM32WBxx_HAL_Driver/Src/stm32wbxx_hal_pka.c. */
#ifdef WOLFSSL_STM32_BARE

/* PKA RAM occupies addresses PKA_BASE+0x400 .. PKA_BASE+0x11F4 on V1 and
 * a slightly larger window on V2. The CMSIS device header sizes the
 * RAM[] array correctly for the part. */
#ifndef PKA_RAM_PARAM_END
/* The HAL macro `__PKA_RAM_PARAM_END(TAB,IDX)` differs by PKA IP rev:
 *   - V1 PKA (WB / WL / L5): writes a single zero word at IDX.
 *   - V2 PKA (WBA / U5 / H5 / N6 / C5 / H7S): writes TWO consecutive
 *     zero words at IDX and IDX+1.
 * On V1 the operand RAM slots are packed tightly and a stray second
 * zero overwrites the first word of the next operand -- on WL55 this
 * silently corrupts ECDSA sign input (HASH_E or PRIVATE_KEY_D depending
 * on which operand is being terminated), producing R/S that don't
 * verify against their own pubkey. On V2 the slot spacing is wider and
 * the spec requires the double-zero terminator (the PKA microcode
 * scans until it sees two zeros).
 *
 * Match the HAL flow exactly by gating on WOLFSSL_STM32_PKA_V2. */
#ifdef WOLFSSL_STM32_PKA_V2
#define PKA_RAM_PARAM_END(RAM, IDX)        \
    do {                                   \
        (RAM)[(IDX)]      = 0UL;           \
        (RAM)[(IDX) + 1U] = 0UL;           \
    } while (0)
#else
#define PKA_RAM_PARAM_END(RAM, IDX)        \
    do { (RAM)[(IDX)] = 0UL; } while (0)
#endif
#endif

/* Mode encoding constants (from stm32wbxx_hal_pka.h and equivalent).
 * Same numeric values across V1 and V2. */
#ifndef PKA_MODE_ECC_MUL
#define PKA_MODE_ECC_MUL              (0x00000020U)
#endif
#ifndef PKA_MODE_ECDSA_VERIFICATION
#define PKA_MODE_ECDSA_VERIFICATION   (0x00000026U)
#endif
#ifndef PKA_MODE_ECDSA_SIGNATURE
#define PKA_MODE_ECDSA_SIGNATURE      (0x00000024U)
#endif

/* Success-code sentinel for RAM[PKA_ECDSA_SIGN_OUT_ERROR] and
 * RAM[PKA_ECDSA_VERIF_OUT_RESULT]. V1 PKA (WB / WL / L5) uses 0 == OK.
 * V2 PKA (WBA / U5 / H5 / N6 / C5 / H7S) uses 0xD60D == PKA_NO_ERROR;
 * 0 is NOT success on V2. Other documented V2 error codes:
 *   0xCBC9 = PKA_FAILED_COMPUTATION
 *   0xA3B7 = PKA_RPART_SIGNATURE_NULL
 *   0xF946 = PKA_SPART_SIGNATURE_NULL
 */
#ifdef WOLFSSL_STM32_PKA_V2
#define WC_STM32_PKA_OK_CODE   0xD60DUL
#else
#define WC_STM32_PKA_OK_CODE   0UL
#endif

/* Number of 32-bit word slots in the PKA RAM (e.g. 894 on WB55 V1).
 * Computed from the RAM byte size / 4 rather than the element count:
 * most CMSIS headers type RAM as uint32_t[], but the STM32C5 header
 * types it as uint8_t[5336], so element-count would yield bytes. The
 * PKA RAM is word-addressed on every part, so byte-size/4 is correct
 * for both. */
#define WC_STM32_PKA_RAM_WORDS \
    (sizeof(((PKA_TypeDef*)0)->RAM) / 4U)

/* Big-endian byte buffer -> PKA RAM (little-endian word order). The
 * destination is the PKA RAM slot indexed by 'word_idx'; n is the byte
 * count of the source. Mirrors PKA_Memcpy_u8_to_u32 in the HAL. */
static void wc_stm32_pka_load_be(volatile uint32_t* dst, const uint8_t* src,
    uint32_t n)
{
    uint32_t index = 0;
    if (dst == NULL || src == NULL) return;

    for (; index < (n / 4U); index++) {
        dst[index] =
            ((uint32_t)src[(n - (index * 4U) - 1U)])              |
            ((uint32_t)src[(n - (index * 4U) - 2U)] <<  8)        |
            ((uint32_t)src[(n - (index * 4U) - 3U)] << 16)        |
            ((uint32_t)src[(n - (index * 4U) - 4U)] << 24);
    }
    if ((n % 4U) == 1U) {
        dst[index] = (uint32_t)src[(n - (index * 4U) - 1U)];
    }
    else if ((n % 4U) == 2U) {
        dst[index] =
            ((uint32_t)src[(n - (index * 4U) - 1U)])              |
            ((uint32_t)src[(n - (index * 4U) - 2U)] <<  8);
    }
    else if ((n % 4U) == 3U) {
        dst[index] =
            ((uint32_t)src[(n - (index * 4U) - 1U)])              |
            ((uint32_t)src[(n - (index * 4U) - 2U)] <<  8)        |
            ((uint32_t)src[(n - (index * 4U) - 3U)] << 16);
    }
}

/* Load an operand into the PKA RAM at `slot` and append the two-word
 * PARAM_END terminator immediately after it. Combines wc_stm32_pka_load_be
 * with PKA_RAM_PARAM_END(), which appear paired at every operand-load
 * site in HAL_PKA_ECCMul / ECDSAVerif / ECDSASign. */
static void wc_stm32_pka_load_param_be(volatile uint32_t* ram, uint32_t slot,
    const uint8_t* src, uint32_t bytes)
{
    wc_stm32_pka_load_be(&ram[slot], src, bytes);
    PKA_RAM_PARAM_END(ram, slot + ((bytes + 3U) / 4U));
}

/* Forward decl -- defined later (HAL_PKA_Init lives after this point but
 * the helper below is referenced from the ECC/ECDSA shim entries which
 * also live later, so the call-site ordering is fine). */
static HAL_StatusTypeDef wc_stm32_pka_ensure_init(PKA_HandleTypeDef *hpkah);

/* Common preamble for the PKA setup entries (ECCMul / ECDSAVerif /
 * ECDSASign): NULL-guard `hpkah`, run ensure_init, NULL-guard the
 * resolved instance, and hand back the RAM pointer. Returns NULL on
 * any failure -- caller maps NULL -> HAL_ERROR. */
static volatile uint32_t* wc_stm32_pka_prep_ram(PKA_HandleTypeDef* hpkah)
{
    HAL_StatusTypeDef st;
    if (hpkah == NULL) return NULL;
    st = wc_stm32_pka_ensure_init(hpkah);
    if (st != HAL_OK) {
#ifdef WC_STM32_PKA_DIAG
        printf("PKA prep_ram init failed=%d\n", (int)st);
#endif
        return NULL;
    }
    if (hpkah->Instance == NULL) {
#ifdef WC_STM32_PKA_DIAG
        printf("PKA prep_ram Instance NULL\n");
#endif
        return NULL;
    }
    /* Cast to word pointer: the STM32C5 CMSIS types PKA RAM as uint8_t[],
     * others as uint32_t[]. Callers word-index the returned pointer, which
     * the PKA RAM requires (byte accesses bus-fault). */
    return (volatile uint32_t*)(void*)hpkah->Instance->RAM;
}

/* PKA RAM (little-endian word order) -> big-endian byte buffer. */
static void wc_stm32_pka_read_be(uint8_t* dst, volatile const uint32_t* src,
    uint32_t n)
{
    uint32_t i = 0;
    if (dst == NULL || src == NULL) return;

    for (; i < (n / 4U); i++) {
        uint32_t off = n - 4U - (i * 4U);
        dst[off + 3U] = (uint8_t)((src[i]      ) & 0xFFU);
        dst[off + 2U] = (uint8_t)((src[i] >>  8) & 0xFFU);
        dst[off + 1U] = (uint8_t)((src[i] >> 16) & 0xFFU);
        dst[off + 0U] = (uint8_t)((src[i] >> 24) & 0xFFU);
    }
    if ((n % 4U) == 1U) {
        dst[0U] = (uint8_t)(src[i] & 0xFFU);
    }
    else if ((n % 4U) == 2U) {
        dst[1U] = (uint8_t)((src[i]      ) & 0xFFU);
        dst[0U] = (uint8_t)((src[i] >>  8) & 0xFFU);
    }
    else if ((n % 4U) == 3U) {
        dst[2U] = (uint8_t)((src[i]      ) & 0xFFU);
        dst[1U] = (uint8_t)((src[i] >>  8) & 0xFFU);
        dst[0U] = (uint8_t)((src[i] >> 16) & 0xFFU);
    }
}

/* Optimal bit-size: bytes * 8 minus the leading-zero count of the MSB
 * (matches PKA_GetOptBitSize_u8 in the HAL). */
static uint32_t wc_stm32_pka_optbits(uint32_t byteNumber, uint8_t msb)
{
    uint32_t pos = 0;
    uint32_t v = msb;
    while (v != 0U) {
        v >>= 1;
        pos++;
    }
    if (byteNumber == 0U) {
        return 0U;
    }
    return ((byteNumber - 1U) * 8U) + pos;
}

#ifndef WC_STM32_PKA_INIT_TIMEOUT
    #define WC_STM32_PKA_INIT_TIMEOUT 0x40000
#endif

static HAL_StatusTypeDef HAL_PKA_Init(PKA_HandleTypeDef *hpkah)
{
    uint32_t t;

    if (hpkah == NULL) {
        return HAL_ERROR;
    }
    if (hpkah->Instance == NULL) {
        hpkah->Instance = PKA;
    }

#ifdef WC_STM32_PKA_CLK_ENABLE
    WC_STM32_PKA_CLK_ENABLE();
#endif

#if defined(WOLFSSL_STM32C5) && defined(RCC_AHB2RSTR_PKARST)
    /* C5A3 silicon (REV_ID=0x2000 in our hand): the PKA IP after the
     * first clock-enable comes up in a state where SR.INITOK never
     * asserts (CR.EN sticks at 1, SR stays 0x00). The HAL works around
     * this with an explicit RCC reset pulse around the first init.
     * Cycle AHB2RSTR.PKARST before driving CR.EN -- this clears
     * whatever latent state blocks the RAM-erase / self-check from
     * completing. Same workaround pattern used for the C5 RNG NIST
     * init in random.c. Other V2 PKA chips don't need this; gated on
     * WOLFSSL_STM32C5. */
    RCC->AHB2RSTR |= RCC_AHB2RSTR_PKARST;
    (void)RCC->AHB2RSTR;
    RCC->AHB2RSTR &= ~RCC_AHB2RSTR_PKARST;
    (void)RCC->AHB2RSTR;
#endif

    /* Enable the PKA. On L5 / U5 / H5 and friends the IP runs an
     * automatic PKA-RAM erase after the first clock-enable; writes to
     * CR.EN are silently dropped until the erase completes. Mirror the
     * HAL behaviour and spin writing EN until the readback sticks.
     * On timeout, clear the Instance pointer so wc_stm32_pka_ensure_init
     * will retry on the next call instead of running ops against a
     * still-disabled IP. */
    t = 0;
    while ((hpkah->Instance->CR & PKA_CR_EN) != PKA_CR_EN) {
        hpkah->Instance->CR = PKA_CR_EN;
        if (++t >= WC_STM32_PKA_INIT_TIMEOUT) {
#ifdef WC_STM32_PKA_DIAG
            printf("PKA Init CR.EN timeout CR=%lx SR=%lx\n",
                (unsigned long)hpkah->Instance->CR,
                (unsigned long)hpkah->Instance->SR);
#endif
            hpkah->Instance = NULL;
            return HAL_TIMEOUT;
        }
    }

#ifdef PKA_SR_INITOK
    /* V2 PKA additionally exposes an INITOK status flag in SR that is
     * set when the RAM-erase + self-check sequence completes. The V2
     * HAL_PKA_Init waits for INITOK before returning. Without this
     * wait, an immediate ECDSA SIGN can race the init and silently
     * fail with OUT_ERROR = 0xCBC9 (PKA_FAILED_COMPUTATION) on U5 / H5
     * / WBA / N6 / C5 / H7S. V1 PKA does not have INITOK and the bit
     * is undefined there. */
    t = 0;
    while ((hpkah->Instance->SR & PKA_SR_INITOK) == 0U) {
        if (++t >= WC_STM32_PKA_INIT_TIMEOUT) {
#ifdef WC_STM32_PKA_DIAG
            printf("PKA Init INITOK timeout CR=%lx SR=%lx\n",
                (unsigned long)hpkah->Instance->CR,
                (unsigned long)hpkah->Instance->SR);
#endif
            hpkah->Instance = NULL;
            return HAL_TIMEOUT;
        }
    }
#endif

    /* Clear any pending flags. */
    hpkah->Instance->CLRFR = PKA_CLRFR_PROCENDFC | PKA_CLRFR_RAMERRFC |
                             PKA_CLRFR_ADDRERRFC;
    return HAL_OK;
}

/* Lazy one-shot init helper. Safe to call from every entry point.
 * Returns HAL_OK if the PKA is ready, HAL_ERROR / HAL_TIMEOUT otherwise.
 * On failure HAL_PKA_Init resets hpkah->Instance back to NULL so the
 * next call retries instead of running ops against a disabled IP. */
static HAL_StatusTypeDef wc_stm32_pka_ensure_init(PKA_HandleTypeDef *hpkah)
{
    if (hpkah == NULL) return HAL_ERROR;
    if (hpkah->Instance == NULL) {
        return HAL_PKA_Init(hpkah);
    }
    return HAL_OK;
}

static void HAL_PKA_RAMReset(PKA_HandleTypeDef *hpkah)
{
    volatile uint32_t* ram;
    uint32_t i;
    if (hpkah == NULL || hpkah->Instance == NULL) return;
    /* Word-addressed: index a uint32_t view, not the CMSIS RAM[] element
     * type (uint8_t[] on STM32C5 -> byte stores, which bus-fault). */
    ram = (volatile uint32_t*)(void*)hpkah->Instance->RAM;
    for (i = 0; i < WC_STM32_PKA_RAM_WORDS; i++) {
        ram[i] = 0UL;
    }
}

/* Generic start-and-poll sequence with bounded timeout. The default
 * spin budget covers a P-521 scalar mul on a slow PKA (worst case on
 * the parts wolfSSL targets is ~2 sec; the budget here is well above
 * that). Override at compile time via WC_STM32_PKA_TIMEOUT_LOOPS. */
#ifndef WC_STM32_PKA_TIMEOUT_LOOPS
#define WC_STM32_PKA_TIMEOUT_LOOPS 0x10000000U
#endif

static HAL_StatusTypeDef wc_stm32_pka_process(PKA_HandleTypeDef *hpkah,
    uint32_t mode)
{
    PKA_TypeDef *p;
    uint32_t cr, t;

    if (hpkah == NULL || hpkah->Instance == NULL) {
        return HAL_ERROR;
    }
    p = hpkah->Instance;

    /* PKA must be enabled before MODE/START are written. */
    if ((p->CR & PKA_CR_EN) == 0U) {
        p->CR = PKA_CR_EN;
    }

    /* Update the mode field in CR; clear ALL interrupt enables including
     * OPERRIE (operation-error) on V2 PKA. The HAL MODIFY_REG clears
     * PROCENDIE | RAMERRIE | ADDRERRIE | OPERRIE -- missing OPERRIE was
     * harmless under polling but inconsistent with the HAL flow. */
    cr = p->CR;
    cr &= ~(PKA_CR_MODE | PKA_CR_PROCENDIE | PKA_CR_RAMERRIE |
            PKA_CR_ADDRERRIE);
#ifdef PKA_CR_OPERRIE
    cr &= ~PKA_CR_OPERRIE;
#endif
    cr |= (mode << PKA_CR_MODE_Pos) & PKA_CR_MODE;
    p->CR = cr;
    __DMB();

    /* Clear any status flags left over from a prior operation before
     * starting this one -- matches the HAL, which clears all of
     * PROCENDF / RAMERRF / ADDRERRF / OPERRF. In particular OPERRF is
     * sticky on some V2 PKA silicon (e.g. STM32H5): a prior operation
     * can latch OPERRF, and because the end-of-op cleanup below does not
     * clear it, the next operation's poll would see the stale OPERRF and
     * abort immediately (reported as WC_HW_E). */
    p->CLRFR = PKA_CLRFR_PROCENDFC | PKA_CLRFR_RAMERRFC | PKA_CLRFR_ADDRERRFC;
#ifdef PKA_CLRFR_OPERRFC
    p->CLRFR = PKA_CLRFR_OPERRFC;
#endif
    __DMB();

    /* Start the operation. */
    p->CR = cr | PKA_CR_START;
    __DMB();

    /* Wait for end-of-operation flag, OR an error flag, OR timeout.
     * Also watch OPERRF on V2 PKA -- the IP silently rejects invalid
     * operand combinations with OPERRF=1 + BUSY=0 + PROCENDF=0, which
     * looks like a hang to a poller that only watches PROCENDF/RAMERRF/
     * ADDRERRF. */
    t = 0;
    while ((p->SR & PKA_SR_PROCENDF) == 0U) {
        uint32_t err_mask = PKA_SR_RAMERRF | PKA_SR_ADDRERRF;
#ifdef PKA_SR_OPERRF
        err_mask |= PKA_SR_OPERRF;
#endif
        if ((p->SR & err_mask) != 0U) {
#ifdef WC_STM32_PKA_DIAG
            printf("PKA err mode=%lx CR=%lx SR=%lx\n",
                (unsigned long)mode, (unsigned long)p->CR,
                (unsigned long)p->SR);
#endif
            p->CLRFR = PKA_CLRFR_PROCENDFC | PKA_CLRFR_RAMERRFC |
                       PKA_CLRFR_ADDRERRFC;
#ifdef PKA_CLRFR_OPERRFC
            p->CLRFR = PKA_CLRFR_OPERRFC;
#endif
            return HAL_ERROR;
        }
        if (++t >= WC_STM32_PKA_TIMEOUT_LOOPS) {
#ifdef WC_STM32_PKA_DIAG
            printf("PKA timeout mode=%lx CR=%lx SR=%lx\n",
                (unsigned long)mode, (unsigned long)p->CR,
                (unsigned long)p->SR);
#endif
            p->CLRFR = PKA_CLRFR_PROCENDFC | PKA_CLRFR_RAMERRFC |
                       PKA_CLRFR_ADDRERRFC;
            return HAL_TIMEOUT;
        }
    }

    /* Clear all status flags. */
    p->CLRFR = PKA_CLRFR_PROCENDFC | PKA_CLRFR_RAMERRFC | PKA_CLRFR_ADDRERRFC;

    return HAL_OK;
}

#ifdef WOLFSSL_STM32C5
/* The STM32C5 PKA implements only the side-channel-PROTECTED ECDSA SIGN
 * (mode 0x24); the plain ECDSA SIGN does not exist. The protected engine
 * requires the operating MODE written to PKA_CR BEFORE the operands are loaded
 * into PKA RAM, on a freshly-erased RAM. The standard V2 flow writes the mode
 * AFTER the operands (correct on U3/U5/N6) and on the C5 yields an operation
 * that completes cleanly (PROCENDF, OUT_ERROR=OK) but returns a WRONG r,s.
 * Arm the mode up front here, on a fresh RAM erase (disable then re-enable ->
 * INITOK). The HW RNG is intentionally left running -- the protected sign
 * chains with it for side-channel blinding (RM0522 Table 241) and signs
 * correctly with it enabled. This is for the SIGN only: ECDSA VERIFY (0x26) is
 * a plain, non-protected public operation and runs the standard V2 path. */
static HAL_StatusTypeDef wc_stm32_pka_arm_mode(PKA_HandleTypeDef *hpkah,
    uint32_t mode)
{
    PKA_TypeDef *p;
    uint32_t cr, t;

    if (hpkah == NULL || hpkah->Instance == NULL) {
        return HAL_ERROR;
    }
    p = hpkah->Instance;

    /* Fresh PKA RAM erase: disable then re-enable, wait for INITOK. */
    p->CR = 0U;
    __DMB();
    p->CR = PKA_CR_EN;
    t = 0;
    while ((p->SR & PKA_SR_INITOK) == 0U) {
        if (++t >= WC_STM32_PKA_TIMEOUT_LOOPS) {
            return HAL_TIMEOUT;
        }
    }
    /* Write the operating mode before the operands are loaded. */
    cr = p->CR;
    cr &= ~PKA_CR_MODE;
    cr |= (mode << PKA_CR_MODE_Pos) & PKA_CR_MODE;
    p->CR = cr;
    __DMB();
    return HAL_OK;
}
#endif /* WOLFSSL_STM32C5 */

static HAL_StatusTypeDef HAL_PKA_ECCMul(PKA_HandleTypeDef *hpkah,
    PKA_ECCMulInTypeDef *in, uint32_t Timeout)
{
    volatile uint32_t *RAM;

    (void)Timeout;
    if (in == NULL) return HAL_ERROR;
    RAM = wc_stm32_pka_prep_ram(hpkah);
    if (RAM == NULL) return HAL_ERROR;

    /* Scalar 'k' bit length, modulus bit length, and 'a' coefficient
     * sign indicator -- exactly as the HAL writes them. The HAL takes
     * the leading byte of the curve ORDER (not the scalar itself) when
     * computing the optimal scalar bit-size on V2 PKA; a small scalar
     * with a zero MSB byte would otherwise report 8 fewer bits than
     * required and the IP accepts the operation but PROCENDF never
     * asserts (timeout, SR=INITOK only). */
    RAM[PKA_ECC_SCALAR_MUL_IN_EXP_NB_BITS] =
#ifdef WOLFSSL_STM32_PKA_V2
        (in->primeOrder != NULL) ?
            wc_stm32_pka_optbits(in->scalarMulSize, *(in->primeOrder)) :
#endif
            wc_stm32_pka_optbits(in->scalarMulSize, *(in->scalarMul));
    RAM[PKA_ECC_SCALAR_MUL_IN_OP_NB_BITS] =
        wc_stm32_pka_optbits(in->modulusSize, *(in->modulus));
    RAM[PKA_ECC_SCALAR_MUL_IN_A_COEFF_SIGN] = in->coefSign;

    /* Match the V2 HAL's RAM write order EXACTLY:
     *   A_COEFF, B_COEFF, MOD_GF, K, INITIAL_POINT_X, INITIAL_POINT_Y,
     *   N_PRIME_ORDER.
     * (V1 PKA has no B_COEFF / N_PRIME_ORDER -- skip those slots.)
     * The RAM slots have disjoint addresses so write order shouldn't
     * matter in theory, but the V2 PKA IP appears to latch SOME state
     * from the write sequence that produces the PROCENDF-never-asserts
     * symptom on every V2 chip if the order differs from the HAL. */
    wc_stm32_pka_load_param_be(RAM, PKA_ECC_SCALAR_MUL_IN_A_COEFF,
        in->coefA, in->modulusSize);
#ifdef WOLFSSL_STM32_PKA_V2
    if (in->coefB != NULL) {
        wc_stm32_pka_load_param_be(RAM, PKA_ECC_SCALAR_MUL_IN_B_COEFF,
            in->coefB, in->modulusSize);
    }
#endif
    wc_stm32_pka_load_param_be(RAM, PKA_ECC_SCALAR_MUL_IN_MOD_GF,
        in->modulus, in->modulusSize);
    wc_stm32_pka_load_param_be(RAM, PKA_ECC_SCALAR_MUL_IN_K,
        in->scalarMul, in->scalarMulSize);
    wc_stm32_pka_load_param_be(RAM, PKA_ECC_SCALAR_MUL_IN_INITIAL_POINT_X,
        in->pointX, in->modulusSize);
    wc_stm32_pka_load_param_be(RAM, PKA_ECC_SCALAR_MUL_IN_INITIAL_POINT_Y,
        in->pointY, in->modulusSize);
#ifdef WOLFSSL_STM32_PKA_V2
    if (in->primeOrder != NULL) {
        wc_stm32_pka_load_param_be(RAM, PKA_ECC_SCALAR_MUL_IN_N_PRIME_ORDER,
            in->primeOrder, in->modulusSize);
    }
#endif /* WOLFSSL_STM32_PKA_V2 */

    return wc_stm32_pka_process(hpkah, PKA_MODE_ECC_MUL);
}

static void HAL_PKA_ECCMul_GetResult(PKA_HandleTypeDef *hpkah,
    PKA_ECCMulOutTypeDef *out)
{
    uint32_t size;
    volatile const uint32_t *RAM;

    if (hpkah == NULL || hpkah->Instance == NULL || out == NULL) return;
    /* Word view: STM32C5 types PKA RAM as uint8_t[]; others as uint32_t[]. */
    RAM = (volatile const uint32_t*)(void*)hpkah->Instance->RAM;

    /* The HAL recomputes the byte size from the saved IN_OP_NB_BITS
     * slot. We do the same. */
    size = (RAM[PKA_ECC_SCALAR_MUL_IN_OP_NB_BITS] + 7U) / 8U;

    if (out->ptX != NULL) {
        wc_stm32_pka_read_be(out->ptX,
            &RAM[PKA_ECC_SCALAR_MUL_OUT_RESULT_X], size);
    }
    if (out->ptY != NULL) {
        wc_stm32_pka_read_be(out->ptY,
            &RAM[PKA_ECC_SCALAR_MUL_OUT_RESULT_Y], size);
    }
}

static HAL_StatusTypeDef HAL_PKA_ECDSAVerif(PKA_HandleTypeDef *hpkah,
    PKA_ECDSAVerifInTypeDef *in, uint32_t Timeout)
{
    volatile uint32_t *RAM;

    (void)Timeout;
    if (in == NULL) return HAL_ERROR;
    RAM = wc_stm32_pka_prep_ram(hpkah);
    if (RAM == NULL) return HAL_ERROR;

    RAM[PKA_ECDSA_VERIF_IN_ORDER_NB_BITS] =
        wc_stm32_pka_optbits(in->primeOrderSize, *(in->primeOrder));
    RAM[PKA_ECDSA_VERIF_IN_MOD_NB_BITS] =
        wc_stm32_pka_optbits(in->modulusSize, *(in->modulus));
    RAM[PKA_ECDSA_VERIF_IN_A_COEFF_SIGN] = in->coefSign;

    wc_stm32_pka_load_param_be(RAM, PKA_ECDSA_VERIF_IN_A_COEFF,
        in->coef, in->modulusSize);
    wc_stm32_pka_load_param_be(RAM, PKA_ECDSA_VERIF_IN_MOD_GF,
        in->modulus, in->modulusSize);
    wc_stm32_pka_load_param_be(RAM, PKA_ECDSA_VERIF_IN_INITIAL_POINT_X,
        in->basePointX, in->modulusSize);
    wc_stm32_pka_load_param_be(RAM, PKA_ECDSA_VERIF_IN_INITIAL_POINT_Y,
        in->basePointY, in->modulusSize);
    wc_stm32_pka_load_param_be(RAM, PKA_ECDSA_VERIF_IN_PUBLIC_KEY_POINT_X,
        in->pPubKeyCurvePtX, in->modulusSize);
    wc_stm32_pka_load_param_be(RAM, PKA_ECDSA_VERIF_IN_PUBLIC_KEY_POINT_Y,
        in->pPubKeyCurvePtY, in->modulusSize);
    wc_stm32_pka_load_param_be(RAM, PKA_ECDSA_VERIF_IN_SIGNATURE_R,
        in->RSign, in->primeOrderSize);
    wc_stm32_pka_load_param_be(RAM, PKA_ECDSA_VERIF_IN_SIGNATURE_S,
        in->SSign, in->primeOrderSize);
    wc_stm32_pka_load_param_be(RAM, PKA_ECDSA_VERIF_IN_HASH_E,
        in->hash, in->primeOrderSize);
    wc_stm32_pka_load_param_be(RAM, PKA_ECDSA_VERIF_IN_ORDER_N,
        in->primeOrder, in->primeOrderSize);

    return wc_stm32_pka_process(hpkah, PKA_MODE_ECDSA_VERIFICATION);
}

static uint32_t HAL_PKA_ECDSAVerif_IsValidSignature(
    PKA_HandleTypeDef const *const hpkah)
{
    if (hpkah == NULL || hpkah->Instance == NULL) return 0U;
    /* IP-rev-aware success check -- see WC_STM32_PKA_OK_CODE definition.
     * Word view: STM32C5 types PKA RAM as uint8_t[]; others as uint32_t[]. */
    return (((volatile const uint32_t*)(void*)hpkah->Instance->RAM)
                [PKA_ECDSA_VERIF_OUT_RESULT] == WC_STM32_PKA_OK_CODE) ? 1U : 0U;
}

static HAL_StatusTypeDef HAL_PKA_ECDSASign(PKA_HandleTypeDef *hpkah,
    PKA_ECDSASignInTypeDef *in, uint32_t Timeout)
{
    volatile uint32_t *RAM;
    HAL_StatusTypeDef st;

    (void)Timeout;
    if (in == NULL) return HAL_ERROR;
    RAM = wc_stm32_pka_prep_ram(hpkah);
    if (RAM == NULL) return HAL_ERROR;

#ifdef WOLFSSL_STM32C5
    /* C5 protected sign (0x24): arm the mode on a fresh RAM erase before the
     * operands are written (see wc_stm32_pka_arm_mode). */
    if (wc_stm32_pka_arm_mode(hpkah, PKA_MODE_ECDSA_SIGNATURE) != HAL_OK) {
        return HAL_ERROR;
    }
#endif

    /* Capture sizes on the handle BEFORE the operation -- V2 PKA
     * clobbers RAM[MOD_NB_BITS] during compute. GetResult reads from
     * the handle on V2 (matches HAL behaviour). */
    hpkah->primeordersize = in->modulusSize;
    RAM[PKA_ECDSA_SIGN_IN_ORDER_NB_BITS] =
        wc_stm32_pka_optbits(in->primeOrderSize, *(in->primeOrder));
    RAM[PKA_ECDSA_SIGN_IN_MOD_NB_BITS] =
        wc_stm32_pka_optbits(in->modulusSize, *(in->modulus));
    RAM[PKA_ECDSA_SIGN_IN_A_COEFF_SIGN] = in->coefSign;

    wc_stm32_pka_load_param_be(RAM, PKA_ECDSA_SIGN_IN_A_COEFF,
        in->coef, in->modulusSize);
#ifdef WOLFSSL_STM32_PKA_V2
    /* V2 PKA ECDSA SIGN requires the curve `b` coefficient loaded
     * between A_COEFF and MOD_GF. V1 PKA has no B_COEFF slot for sign.
     * Without B_COEFF the V2 sign operation reports
     * OUT_ERROR = 0xCBC9 (PKA_FAILED_COMPUTATION) and aborts. The HAL
     * `PKA_ECDSASign_Set` writes this between A_COEFF and MOD_GF. */
    if (in->coefB != NULL) {
        wc_stm32_pka_load_param_be(RAM, PKA_ECDSA_SIGN_IN_B_COEFF,
            in->coefB, in->modulusSize);
    }
#endif
    wc_stm32_pka_load_param_be(RAM, PKA_ECDSA_SIGN_IN_MOD_GF,
        in->modulus, in->modulusSize);
    wc_stm32_pka_load_param_be(RAM, PKA_ECDSA_SIGN_IN_K,
        in->integer, in->primeOrderSize);
    wc_stm32_pka_load_param_be(RAM, PKA_ECDSA_SIGN_IN_INITIAL_POINT_X,
        in->basePointX, in->modulusSize);
    wc_stm32_pka_load_param_be(RAM, PKA_ECDSA_SIGN_IN_INITIAL_POINT_Y,
        in->basePointY, in->modulusSize);
    wc_stm32_pka_load_param_be(RAM, PKA_ECDSA_SIGN_IN_HASH_E,
        in->hash, in->primeOrderSize);
    wc_stm32_pka_load_param_be(RAM, PKA_ECDSA_SIGN_IN_PRIVATE_KEY_D,
        in->privateKey, in->primeOrderSize);
    wc_stm32_pka_load_param_be(RAM, PKA_ECDSA_SIGN_IN_ORDER_N,
        in->primeOrder, in->primeOrderSize);

    st = wc_stm32_pka_process(hpkah, PKA_MODE_ECDSA_SIGNATURE);
    if (st != HAL_OK) {
        return st;
    }
    /* Sign reports failure via PKA_ECDSA_SIGN_OUT_ERROR != OK_CODE
     * (e.g. unsuitable random k -- caller is expected to retry).
     * See WC_STM32_PKA_OK_CODE for the V1/V2 sentinel divergence. */
    {
        uint32_t err_code = RAM[PKA_ECDSA_SIGN_OUT_ERROR];
        if (err_code != WC_STM32_PKA_OK_CODE) {
#ifdef WC_STM32_PKA_DIAG
            printf("PKA sign OUT_ERROR=%lx\n", (unsigned long)err_code);
#endif
            return HAL_ERROR;
        }
    }
    return HAL_OK;
}

static void HAL_PKA_ECDSASign_GetResult(PKA_HandleTypeDef *hpkah,
    PKA_ECDSASignOutTypeDef *out,
    PKA_ECDSASignOutExtParamTypeDef *outExt)
{
    uint32_t size;
    volatile const uint32_t *RAM;

    if (hpkah == NULL || hpkah->Instance == NULL) return;
    /* Word view: STM32C5 types PKA RAM as uint8_t[]; others as uint32_t[]. */
    RAM = (volatile const uint32_t*)(void*)hpkah->Instance->RAM;
    /* V2 PKA clobbers RAM[MOD_NB_BITS] during compute; use the size
     * saved on the handle. V1 still reads from RAM. */
#ifdef WOLFSSL_STM32_PKA_V2
    size = hpkah->primeordersize;
#else
    size = (RAM[PKA_ECDSA_SIGN_IN_MOD_NB_BITS] + 7U) / 8U;
#endif

    if (out != NULL) {
        if (out->RSign != NULL) {
            wc_stm32_pka_read_be(out->RSign,
                &RAM[PKA_ECDSA_SIGN_OUT_SIGNATURE_R], size);
        }
        if (out->SSign != NULL) {
            wc_stm32_pka_read_be(out->SSign,
                &RAM[PKA_ECDSA_SIGN_OUT_SIGNATURE_S], size);
        }
    }
    if (outExt != NULL) {
        if (outExt->ptX != NULL) {
            wc_stm32_pka_read_be(outExt->ptX,
                &RAM[PKA_ECDSA_SIGN_OUT_FINAL_POINT_X], size);
        }
        if (outExt->ptY != NULL) {
            wc_stm32_pka_read_be(outExt->ptY,
                &RAM[PKA_ECDSA_SIGN_OUT_FINAL_POINT_Y], size);
        }
    }
}

#endif /* WOLFSSL_STM32_BARE */

#endif /* WOLFSSL_STM32_PKA */


#ifdef STM32_HASH

#if defined(WOLFSSL_STM32_BARE) && !defined(WC_STM32_HASH_CLK_ENABLE)
    #error "WOLFSSL_STM32_BARE: HASH clock-enable not mapped for this STM32 \
        family. Add WC_STM32_HASH_CLK_ENABLE() to \
        wolfssl/wolfcrypt/port/st/stm32.h, or define NO_STM32_HASH."
#endif

/* User can override STM32_HASH_CLOCK_ENABLE and STM32_HASH_CLOCK_DISABLE */
#ifndef STM32_HASH_CLOCK_ENABLE
    static WC_INLINE void wc_Stm32_Hash_Clock_Enable(STM32_HASH_Context* stmCtx)
    {
    #if defined(WOLFSSL_STM32_BARE)
        WC_STM32_HASH_CLK_ENABLE();
    #elif defined(WOLFSSL_STM32_CUBEMX)
        __HAL_RCC_HASH_CLK_ENABLE();
    #else
        RCC_AHB2PeriphClockCmd(RCC_AHB2Periph_HASH, ENABLE);
    #endif
        (void)stmCtx;
    }
    #define STM32_HASH_CLOCK_ENABLE(ctx) wc_Stm32_Hash_Clock_Enable(ctx)
#endif

#ifndef STM32_HASH_CLOCK_DISABLE
    static WC_INLINE void wc_Stm32_Hash_Clock_Disable(STM32_HASH_Context* stmCtx)
    {
    #if defined(WOLFSSL_STM32_BARE)
        WC_STM32_HASH_CLK_DISABLE();
    #elif defined(WOLFSSL_STM32_CUBEMX)
        __HAL_RCC_HASH_CLK_DISABLE();
    #else
        RCC_AHB2PeriphClockCmd(RCC_AHB2Periph_HASH, DISABLE);
    #endif
        (void)stmCtx;
    }
    #define STM32_HASH_CLOCK_DISABLE(ctx) wc_Stm32_Hash_Clock_Disable(ctx)
#endif


/* STM32 Port Internal Functions */
static void wc_Stm32_Hash_NumValidBits(word32 len)
{
    /* calculate number of valid bits in last word */
    /* NBLW = 0x00 (all 32-bits are valid) */
    word32 nbvalidbytesdata = (len % STM32_HASH_REG_SIZE);
    HASH->STR &= ~HASH_STR_NBW;
    HASH->STR |= (8 * nbvalidbytesdata) & HASH_STR_NBW;

#ifdef DEBUG_STM32_HASH
    printf("STM Valid Last bits (%d)\n", 8 * nbvalidbytesdata);
#endif
}

static void wc_Stm32_Hash_SaveContext(STM32_HASH_Context* ctx)
{
    int i;

    /* save context registers */
    ctx->HASH_IMR = HASH->IMR;
    ctx->HASH_STR = HASH->STR;
    ctx->HASH_CR  = HASH->CR;
#ifdef STM32_HASH_SHA3
    ctx->SHA3CFGR  = HASH->SHA3CFGR;
#endif
    for (i=0; i<HASH_CR_SIZE; i++) {
        ctx->HASH_CSR[i] = HASH->CSR[i];
    }

#ifdef DEBUG_STM32_HASH
    printf("STM Save CR %lx, IMR %lx, STR %lx\n",
        HASH->CR, HASH->IMR, HASH->STR);
#endif
}

static void wc_Stm32_Hash_RestoreContext(STM32_HASH_Context* ctx, word32 algo,
    word32 mode)
{
    int i;

    if (ctx->HASH_CR == 0) {
        /* init context */

    #if defined(HASH_IMR_DINIE) && defined(HASH_IMR_DCIE)
        /* Disable IRQ's - wolfSSL does not use the HASH/RNG IRQ
         * If using the HAL hashing API's directly it will re-enable the IRQs */
        HASH->IMR &= ~(HASH_IMR_DINIE | HASH_IMR_DCIE);
    #endif

        /* Configure algorithm, mode, data type and initialize HASH processor.
         * INIT must be written in the same register write as ALGO because
         * setting INIT resets ALGO bits to their default value (MD5). */
        HASH->CR = (algo | mode | HASH_DATATYPE_8B | HASH_CR_INIT);

        /* by default mark all bits valid */
        wc_Stm32_Hash_NumValidBits(0);

#ifdef DEBUG_STM32_HASH
        printf("STM Init algo %x, mode %x, CR %lx, SR %lx\n",
            (unsigned int)algo, (unsigned int)mode,
            HASH->CR, HASH->SR);
#endif
    }
    else {
        /* restore context registers */
        HASH->IMR = ctx->HASH_IMR;
        HASH->STR = ctx->HASH_STR;
#ifdef STM32_HASH_SHA3
        HASH->SHA3CFGR = ctx->SHA3CFGR;
#endif

        /* Restore CR with INIT in a single write - setting INIT resets ALGO
         * bits, so we must include the saved CR value in the same write. */
        HASH->CR = ctx->HASH_CR | HASH_CR_INIT;

        /* continue restoring context registers */
        for (i=0; i<HASH_CR_SIZE; i++) {
            HASH->CSR[i] = ctx->HASH_CSR[i];
        }

#ifdef DEBUG_STM32_HASH
        printf("STM Restore CR %lx, IMR %lx, STR %lx\n",
            HASH->CR, HASH->IMR, HASH->STR);
#endif
    }
}

static void wc_Stm32_Hash_GetDigest(byte* hash, int digestSize)
{
    word32 digest[HASH_MAX_DIGEST/sizeof(word32)];
    int i = 0, sz;

    if (digestSize > HASH_MAX_DIGEST)
        digestSize = HASH_MAX_DIGEST;

    sz = digestSize;
    while (sz > 0) {
        /* first 20 bytes come from the instance digest registers. The
         * new-generation HASH IP (gated via WC_STM32_HASH_INSTANCE_HRA
         * in stm32.h based on the per-family CMSIS shape) renames this
         * from `HR[5]` to `HRA[5]` and adds a separate `HASH_DIGEST->HR[16]`
         * for the full digest; the legacy F4/F7/L4 layout still exposes
         * `HR[5]` directly on the instance. */
        if (i < 5) {
        #ifdef WC_STM32_HASH_INSTANCE_HRA
            digest[i] = HASH->HRA[i];
        #else
            digest[i] = HASH->HR[i];
        #endif
        }
    #ifdef HASH_DIGEST
        /* reset comes from HASH_DIGEST */
        else {
            digest[i] = HASH_DIGEST->HR[i];
        }
    #endif
        i++;
        sz -= 4;
    }

    ByteReverseWords(digest, digest, digestSize);

    XMEMCPY(hash, digest, digestSize);

#ifdef DEBUG_STM32_HASH
    {
        word32 ii;
        printf("STM Digest %d\n", digestSize);
        for (ii=0; ii<digestSize/sizeof(word32); ii++) {
            printf("\tDIG 0x%04x\n", digest[ii]);
        }
    }
#endif
}

static int wc_Stm32_Hash_WaitDataReady(STM32_HASH_Context* stmCtx)
{
    int timeout = 0;
    (void)stmCtx;

    /* wait until not busy and data input buffer ready */
    while (((HASH->SR & HASH_SR_BUSY)
        #ifdef HASH_IMR_DINIE
            || (HASH->SR & HASH_SR_DINIS) == 0
        #endif
        ) && ++timeout < STM32_HASH_TIMEOUT) {
    };

#ifdef DEBUG_STM32_HASH
    printf("STM Wait Data %d, HASH->SR %lx\n", timeout, HASH->SR);
#endif

    /* verify timeout did not occur */
    if (timeout >= STM32_HASH_TIMEOUT) {
        return WC_TIMEOUT_E;
    }
    return 0;
}

static int wc_Stm32_Hash_WaitCalcComp(STM32_HASH_Context* stmCtx)
{
    int timeout = 0;
    (void)stmCtx;

    /* wait until not busy and hash digest calculation complete */
    while (((HASH->SR & HASH_SR_BUSY)
        #ifdef HASH_IMR_DCIE
            || (HASH->SR & HASH_SR_DCIS) == 0
        #endif
        ) && ++timeout < STM32_HASH_TIMEOUT) {
    };

#ifdef DEBUG_STM32_HASH
    printf("STM Wait Calc %d, HASH->SR %lx\n", timeout, HASH->SR);
#endif

    /* verify timeout did not occur */
    if (timeout >= STM32_HASH_TIMEOUT) {
        return WC_TIMEOUT_E;
    }
    return 0;
}

static void wc_Stm32_Hash_Data(STM32_HASH_Context* stmCtx, word32 len)
{
    word32 i, blocks;

    if (len > stmCtx->buffLen)
        len = stmCtx->buffLen;

    /* calculate number of 32-bit blocks - round up */
    blocks = ((len + STM32_HASH_REG_SIZE-1) / STM32_HASH_REG_SIZE);
#ifdef DEBUG_STM32_HASH
    printf("STM DIN %d blocks\n", blocks);
#endif
    for (i=0; i<blocks; i++) {
    #ifdef DEBUG_STM32_HASH
        printf("\tDIN 0x%04x\n", stmCtx->buffer[i]);
    #endif
        HASH->DIN = stmCtx->buffer[i];
    }
    stmCtx->loLen += len; /* total */
    stmCtx->buffLen -= len;
    if (stmCtx->buffLen > 0) {
        XMEMMOVE(stmCtx->buffer, (byte*)stmCtx->buffer+len, stmCtx->buffLen);
    }
}


/* STM32 Port Exposed Functions */
void wc_Stm32_Hash_Init(STM32_HASH_Context* stmCtx)
{
    /* clear context */
    /* this also gets called after finish */
    XMEMSET(stmCtx, 0, sizeof(STM32_HASH_Context));
}

int wc_Stm32_Hash_Update(STM32_HASH_Context* stmCtx, word32 algo,
    const byte* data, word32 len, word32 blockSize)
{
    int ret = 0;
    byte* local = (byte*)stmCtx->buffer;
    int wroteToFifo = 0;
    word32 chunkSz;

#ifdef DEBUG_STM32_HASH
    printf("STM Hash Update: algo %x, len %d, buffLen %d, fifoBytes %d\n",
        algo, len, stmCtx->buffLen, stmCtx->fifoBytes);
#endif
    (void)blockSize;

    /* check that internal buffLen is valid */
    if (stmCtx->buffLen > (word32)sizeof(stmCtx->buffer)) {
        return BUFFER_E;
    }

    /* turn on hash clock */
    STM32_HASH_CLOCK_ENABLE(stmCtx);

    /* restore hash context or init as new hash */
    wc_Stm32_Hash_RestoreContext(stmCtx, algo, HASH_ALGOMODE_HASH);

    /* write blocks to FIFO */
    while (len) {
        word32 add;

        chunkSz = blockSize;
        /* fill the FIFO plus one additional to flush the first block */
        if (!stmCtx->fifoBytes) {
            chunkSz += STM32_HASH_REG_SIZE;
        }

        add = min(len, chunkSz - stmCtx->buffLen);
        XMEMCPY(&local[stmCtx->buffLen], data, add);

        stmCtx->buffLen += add;
        data            += add;
        len             -= add;

        if (stmCtx->buffLen == chunkSz) {
            wc_Stm32_Hash_Data(stmCtx, stmCtx->buffLen);
            wroteToFifo = 1;
            stmCtx->fifoBytes += chunkSz;
        }
    }

    if (wroteToFifo) {
        /* make sure hash operation is done */
        ret = wc_Stm32_Hash_WaitDataReady(stmCtx);

        /* save hash state for next operation */
        wc_Stm32_Hash_SaveContext(stmCtx);
    }

    /* turn off hash clock */
    STM32_HASH_CLOCK_DISABLE(stmCtx);

    return ret;
}

int wc_Stm32_Hash_Final(STM32_HASH_Context* stmCtx, word32 algo,
    byte* hash, word32 digestSize)
{
    int ret = 0;

#ifdef DEBUG_STM32_HASH
    printf("STM Hash Final: algo %x, digestSz %d, buffLen %d, fifoBytes %d\n",
        algo, digestSize, stmCtx->buffLen, stmCtx->fifoBytes);
#endif

    /* turn on hash clock */
    STM32_HASH_CLOCK_ENABLE(stmCtx);

    /* restore hash context or init as new hash */
    wc_Stm32_Hash_RestoreContext(stmCtx, algo, HASH_ALGOMODE_HASH);

    /* finish reading any trailing bytes into FIFO */
    if (stmCtx->buffLen > 0) {
        /* send remainder of data */
        wc_Stm32_Hash_Data(stmCtx, stmCtx->buffLen);
    }

    /* calculate number of valid bits in last word */
    wc_Stm32_Hash_NumValidBits(stmCtx->loLen + stmCtx->buffLen);

    /* start hash processor */
    HASH->STR |= HASH_STR_DCAL;

    /* wait for hash done */
    ret = wc_Stm32_Hash_WaitCalcComp(stmCtx);
    if (ret == 0) {
        /* read message digest */
        wc_Stm32_Hash_GetDigest(hash, digestSize);
    }

    /* turn off hash clock */
    STM32_HASH_CLOCK_DISABLE(stmCtx);

    return ret;
}

#if defined(STM32_HMAC) && !defined(NO_HMAC)

/* STM32 Port HMAC Functions */
#include <wolfssl/wolfcrypt/hmac.h>

int wc_Stm32_Hmac_GetAlgoInfo(int macType, word32* algo, word32* blockSize,
    word32* digestSize)
{
    int ret = 0;

    switch (macType) {
    #if !defined(NO_MD5) && !defined(STM32_NOMD5)
        case WC_MD5:
            if (algo)       *algo = HASH_AlgoSelection_MD5;
            if (blockSize)  *blockSize = WC_MD5_BLOCK_SIZE;
            if (digestSize) *digestSize = WC_MD5_DIGEST_SIZE;
            break;
    #endif
    #ifndef NO_SHA
        case WC_SHA:
            if (algo)       *algo = HASH_AlgoSelection_SHA1;
            if (blockSize)  *blockSize = WC_SHA_BLOCK_SIZE;
            if (digestSize) *digestSize = WC_SHA_DIGEST_SIZE;
            break;
    #endif
    #ifdef WOLFSSL_SHA224
        case WC_SHA224:
            if (algo)       *algo = HASH_AlgoSelection_SHA224;
            if (blockSize)  *blockSize = WC_SHA224_BLOCK_SIZE;
            if (digestSize) *digestSize = WC_SHA224_DIGEST_SIZE;
            break;
    #endif
    #ifndef NO_SHA256
        case WC_SHA256:
            if (algo)       *algo = HASH_AlgoSelection_SHA256;
            if (blockSize)  *blockSize = WC_SHA256_BLOCK_SIZE;
            if (digestSize) *digestSize = WC_SHA256_DIGEST_SIZE;
            break;
    #endif
    #if defined(STM32_HASH_SHA384) && defined(WOLFSSL_SHA384)
        case WC_SHA384:
            if (algo)       *algo = HASH_ALGOSELECTION_SHA384;
            if (blockSize)  *blockSize = WC_SHA384_BLOCK_SIZE;
            if (digestSize) *digestSize = WC_SHA384_DIGEST_SIZE;
            break;
    #endif
    #if defined(STM32_HASH_SHA512) && defined(WOLFSSL_SHA512)
        case WC_SHA512:
            if (algo)       *algo = HASH_ALGOSELECTION_SHA512;
            if (blockSize)  *blockSize = WC_SHA512_BLOCK_SIZE;
            if (digestSize) *digestSize = WC_SHA512_DIGEST_SIZE;
            break;
    #endif
        default:
            ret = BAD_FUNC_ARG;
            break;
    }

    return ret;
}

static void wc_Stm32_Hmac_FeedKey(const byte* key, word32 keySz)
{
    word32 i, blocks;
    word32 tmp;

    /* feed key words into HASH->DIN */
    blocks = keySz / STM32_HASH_REG_SIZE;
    for (i = 0; i < blocks; i++) {
        XMEMCPY(&tmp, key + (i * STM32_HASH_REG_SIZE), STM32_HASH_REG_SIZE);
        HASH->DIN = tmp;
    }
    /* handle remaining bytes in last partial word */
    if (keySz % STM32_HASH_REG_SIZE) {
        tmp = 0;
        XMEMCPY(&tmp, key + (blocks * STM32_HASH_REG_SIZE),
            keySz % STM32_HASH_REG_SIZE);
        HASH->DIN = tmp;
    }
    ForceZero(&tmp, sizeof(tmp));

#ifdef DEBUG_STM32_HASH
    printf("STM HMAC FeedKey %d bytes\n", (int)keySz);
#endif
}


/* STM32 HMAC Exposed Functions */

int wc_Stm32_Hmac_SetKey(STM32_HASH_Context* stmCtx, int macType,
    const byte* key, word32 keySz)
{
    int ret;
    word32 algo, blockSize, digestSize;
    word32 mode;

    if (stmCtx == NULL || key == NULL)
        return BAD_FUNC_ARG;

    ret = wc_Stm32_Hmac_GetAlgoInfo(macType, &algo, &blockSize, &digestSize);
    if (ret != 0)
        return ret;

#ifdef DEBUG_STM32_HASH
    printf("STM HMAC SetKey: macType %d, keySz %d\n", macType, (int)keySz);
#endif

    /* clear context for fresh HMAC */
    wc_Stm32_Hash_Init(stmCtx);

    /* turn on hash clock */
    STM32_HASH_CLOCK_ENABLE(stmCtx);

    /* initialize hardware for HMAC mode.
     * Keys are always pre-hashed in software before reaching this point
     * (see hmac.c), so keySz will always be <= blockSize here. */
    mode = HASH_ALGOMODE_HMAC;
    wc_Stm32_Hash_RestoreContext(stmCtx, algo, mode);

    /* Phase 1: Feed key into HASH->DIN */
    wc_Stm32_Hmac_FeedKey(key, keySz);

    /* set number of valid bits in last word and trigger DCAL */
    wc_Stm32_Hash_NumValidBits(keySz);
    HASH->STR |= HASH_STR_DCAL;

    /* wait for data input ready (phase 1 complete) */
    ret = wc_Stm32_Hash_WaitDataReady(stmCtx);

    if (ret == 0) {
        /* save context for context switching */
        wc_Stm32_Hash_SaveContext(stmCtx);
    }

    /* turn off hash clock */
    STM32_HASH_CLOCK_DISABLE(stmCtx);

    return ret;
}

int wc_Stm32_Hmac_Final(STM32_HASH_Context* stmCtx, word32 algo,
    const byte* key, word32 keySz, byte* hash, word32 digestSize)
{
    int ret;

    if (stmCtx == NULL || key == NULL || hash == NULL)
        return BAD_FUNC_ARG;

#ifdef DEBUG_STM32_HASH
    printf("STM HMAC Final: algo %x, keySz %d, buffLen %d, fifoBytes %d\n",
        (unsigned int)algo, (int)keySz, (int)stmCtx->buffLen,
        (int)stmCtx->fifoBytes);
#endif

    /* turn on hash clock */
    STM32_HASH_CLOCK_ENABLE(stmCtx);

    /* restore HMAC context */
    wc_Stm32_Hash_RestoreContext(stmCtx, algo, HASH_ALGOMODE_HMAC);

    /* finish reading any trailing bytes into FIFO */
    if (stmCtx->buffLen > 0) {
        wc_Stm32_Hash_Data(stmCtx, stmCtx->buffLen);
    }

    /* Phase 2 complete: set valid bits and trigger DCAL */
    wc_Stm32_Hash_NumValidBits(stmCtx->loLen + stmCtx->buffLen);
    HASH->STR |= HASH_STR_DCAL;

    /* wait for data input ready (phase 2 complete, ready for phase 3) */
    ret = wc_Stm32_Hash_WaitDataReady(stmCtx);
    if (ret != 0) {
        STM32_HASH_CLOCK_DISABLE(stmCtx);
        return ret;
    }

    /* Phase 3: Feed key again into HASH->DIN */
    wc_Stm32_Hmac_FeedKey(key, keySz);

    /* set valid bits for key and trigger DCAL */
    wc_Stm32_Hash_NumValidBits(keySz);
    HASH->STR |= HASH_STR_DCAL;

    /* wait for hash done (digest computation complete) */
    ret = wc_Stm32_Hash_WaitCalcComp(stmCtx);
    if (ret == 0) {
        /* read message digest */
        wc_Stm32_Hash_GetDigest(hash, digestSize);
    }

    /* turn off hash clock */
    STM32_HASH_CLOCK_DISABLE(stmCtx);

    return ret;
}

#endif /* STM32_HMAC && !NO_HMAC */

#endif /* STM32_HASH */


#ifdef STM32_CRYPTO

#ifndef NO_AES
#ifdef WOLFSSL_STM32_BARE

/* Only complain if the user actually asked for STM32 HW AES.
 * `STM32_CRYPTO` is the umbrella enable; without it the BARE driver
 * is dead code and missing clock-enable macros for the family are
 * harmless (e.g. F767 / F303 / G491 ship NO_STM32_CRYPTO). */
#if defined(STM32_CRYPTO) && !defined(WC_STM32_AES_CLK_ENABLE)
    #error "WOLFSSL_STM32_BARE: AES clock-enable not mapped for this STM32 \
        family. Add WC_STM32_AES_CLK_ENABLE() to \
        wolfssl/wolfcrypt/port/st/stm32.h, or define NO_STM32_CRYPTO."
#endif

/* ===== Bare-metal direct-register AES driver =====
 * No HAL or StdPeriph. Two IP variants:
 *   - CRYP (FIFO-based):  F2/F4/F7/H7/MP13
 *   - AES/SAES (TinyAES): L4/L5/U5/H573/G0/G4/WB/WL/WBA/H7S(via SAES)
 *
 * H7S3 has both a "fat" CRYP (same register shape as H753) AND a
 * TinyAES-shape SAES. ST's H7S Cube examples drive AES exclusively via
 * SAES -- the plain CRYP is gated behind the security domain. The H7S
 * arm therefore goes through the TinyAES branch with WC_STM32_AES_INST
 * = SAES (forced via WOLFSSL_STM32_USE_SAES in the per-board settings).
 * Variant selected via family ifdefs below. */

#if defined(WOLFSSL_STM32F2) || defined(WOLFSSL_STM32F4) || \
    defined(WOLFSSL_STM32F7) || defined(WOLFSSL_STM32H7) || \
    defined(WOLFSSL_STM32MP13)
/* ----- CRYP IP (FIFO-based) ----- */

#ifndef STM32_BARE_AES_TIMEOUT
    #define STM32_BARE_AES_TIMEOUT 0x10000
#endif

/* DATATYPE = 10b (byte) so CRYP byte-swaps DR/DOUT for us; key/IV regs are
 * still big-endian. Key arrives pre-reversed via wc_AesSetKey (aes.c:4161);
 * IV is byte-reversed locally before write. */
#define STM32_CRYP_DATATYPE_BYTE  CRYP_CR_DATATYPE_1

static int Stm32AesWaitBusy(void)
{
    int t = 0;
    while ((CRYP->SR & CRYP_SR_BUSY) != 0) {
        if (++t >= STM32_BARE_AES_TIMEOUT) {
            return WC_TIMEOUT_E;
        }
    }
    return 0;
}

static int Stm32AesWaitInNotFull(void)
{
    int t = 0;
    while ((CRYP->SR & CRYP_SR_IFNF) == 0) {
        if (++t >= STM32_BARE_AES_TIMEOUT) {
            return WC_TIMEOUT_E;
        }
    }
    return 0;
}

static int Stm32AesWaitOutNotEmpty(void)
{
    int t = 0;
    while ((CRYP->SR & CRYP_SR_OFNE) == 0) {
        if (++t >= STM32_BARE_AES_TIMEOUT) {
            return WC_TIMEOUT_E;
        }
    }
    return 0;
}

static word32 Stm32AesKeySizeBits(word32 keyLen)
{
    if (keyLen == 24) {
        return CRYP_CR_KEYSIZE_0; /* 192-bit */
    }
    if (keyLen == 32) {
        return CRYP_CR_KEYSIZE_1; /* 256-bit */
    }
    return 0;                     /* 128-bit */
}

/* aes->key is pre-byte-reversed by wc_AesSetKey under BARE (aes.c:4161),
 * so the key words go straight into the K registers in big-endian form. */
static void Stm32AesLoadKey(const word32* key, word32 keyLen)
{
    if (keyLen == 16) {
        CRYP->K2LR = key[0]; CRYP->K2RR = key[1];
        CRYP->K3LR = key[2]; CRYP->K3RR = key[3];
    }
    else if (keyLen == 24) {
        CRYP->K1LR = key[0]; CRYP->K1RR = key[1];
        CRYP->K2LR = key[2]; CRYP->K2RR = key[3];
        CRYP->K3LR = key[4]; CRYP->K3RR = key[5];
    }
    else { /* 32 */
        CRYP->K0LR = key[0]; CRYP->K0RR = key[1];
        CRYP->K1LR = key[2]; CRYP->K1RR = key[3];
        CRYP->K2LR = key[4]; CRYP->K2RR = key[5];
        CRYP->K3LR = key[6]; CRYP->K3RR = key[7];
    }
}

/* aes->reg (IV) is NOT pre-reversed by wc_AesSetIV, so byte-reverse here so
 * the IV registers see big-endian words. */
static void Stm32AesLoadIV(const byte* iv, word32 ivLen)
{
    word32 v[4];
    word32 copyLen = (ivLen > 16) ? 16 : ivLen;

    XMEMSET(v, 0, sizeof(v));
    if (iv != NULL && copyLen > 0) {
        XMEMCPY(v, iv, copyLen);
        ByteReverseWords(v, v, 16);
    }
    CRYP->IV0LR = v[0]; CRYP->IV0RR = v[1];
    CRYP->IV1LR = v[2]; CRYP->IV1RR = v[3];
}

/* Push 4 input words then drain 4 output words. */
static int Stm32AesXferBlock(const byte* in, byte* out)
{
    int ret;
    word32 i;
    word32 buf[WC_AES_BLOCK_SIZE/sizeof(word32)];

    /* Local word-aligned copy so callers may pass byte-aligned ptrs. */
    XMEMCPY(buf, in, WC_AES_BLOCK_SIZE);

    for (i = 0; i < 4; i++) {
        ret = Stm32AesWaitInNotFull();
        if (ret != 0) {
            return ret;
        }
        CRYP->DIN = buf[i];
    }
    for (i = 0; i < 4; i++) {
        ret = Stm32AesWaitOutNotEmpty();
        if (ret != 0) {
            return ret;
        }
        buf[i] = CRYP->DOUT;
    }
    XMEMCPY(out, buf, WC_AES_BLOCK_SIZE);
    return 0;
}

/* CBC/ECB decrypt requires a key-prep pass first (per F4/H7 reference manual:
 * load key, run ALGOMODE=AES_KEY, wait BUSY=0, then start the actual op). */
static int Stm32AesPrepareKey(word32 keyLen)
{
    int ret;

    CRYP->CR = CRYP_CR_ALGOMODE_AES_KEY |
               STM32_CRYP_DATATYPE_BYTE |
               Stm32AesKeySizeBits(keyLen);
    CRYP->CR |= CRYP_CR_CRYPEN;
    ret = Stm32AesWaitBusy();
    CRYP->CR &= ~CRYP_CR_CRYPEN;
    return ret;
}

int wc_Stm32_Aes_Ecb(struct Aes* aes, byte* out, const byte* in,
                     word32 sz, int isEnc)
{
    int ret;
    word32 keyLen, blocks, b;
    word32 cr;

    if (aes == NULL || out == NULL || in == NULL) {
        return BAD_FUNC_ARG;
    }
    if (sz == 0 || (sz % WC_AES_BLOCK_SIZE) != 0) {
        return BAD_FUNC_ARG;
    }

    ret = wc_AesGetKeySize(aes, &keyLen);
    if (ret != 0) {
        return ret;
    }

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }

    WC_STM32_AES_CLK_ENABLE();

    Stm32AesLoadKey(aes->key, keyLen);
    if (!isEnc) {
        ret = Stm32AesPrepareKey(keyLen);
        if (ret != 0) {
            goto exit;
        }
    }

    cr = CRYP_CR_ALGOMODE_AES_ECB |
         STM32_CRYP_DATATYPE_BYTE |
         Stm32AesKeySizeBits(keyLen);
    if (!isEnc) {
        cr |= CRYP_CR_ALGODIR;
    }
    CRYP->CR = cr;
    CRYP->CR |= CRYP_CR_FFLUSH;
    CRYP->CR |= CRYP_CR_CRYPEN;

    blocks = sz / WC_AES_BLOCK_SIZE;
    for (b = 0; b < blocks; b++) {
        ret = Stm32AesXferBlock(in  + b * WC_AES_BLOCK_SIZE,
                                out + b * WC_AES_BLOCK_SIZE);
        if (ret != 0) {
            break;
        }
    }

exit:
    CRYP->CR &= ~CRYP_CR_CRYPEN;
    wolfSSL_CryptHwMutexUnLock();
    return ret;
}

int wc_Stm32_Aes_Cbc(struct Aes* aes, byte* out, const byte* in,
                     word32 sz, int isEnc)
{
    int ret;
    word32 keyLen, blocks, b;
    word32 cr;

    if (aes == NULL || out == NULL || in == NULL) {
        return BAD_FUNC_ARG;
    }
    /* Match the SW / CUBEMX CBC backends: process whole blocks and ignore any
     * sub-block remainder. (The bare wc_AesCbcEncrypt/Decrypt wrappers reject a
     * non-block-multiple length with BAD_LENGTH_E only under
     * WOLFSSL_AES_CBC_LENGTH_CHECKS.) */
    blocks = sz / WC_AES_BLOCK_SIZE;
    if (blocks == 0) {
        return 0;
    }

    ret = wc_AesGetKeySize(aes, &keyLen);
    if (ret != 0) {
        return ret;
    }

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }

    WC_STM32_AES_CLK_ENABLE();

    Stm32AesLoadKey(aes->key, keyLen);
    if (!isEnc) {
        ret = Stm32AesPrepareKey(keyLen);
        if (ret != 0) {
            goto exit;
        }
    }
    Stm32AesLoadIV((const byte*)aes->reg, WC_AES_BLOCK_SIZE);

    cr = CRYP_CR_ALGOMODE_AES_CBC |
         STM32_CRYP_DATATYPE_BYTE |
         Stm32AesKeySizeBits(keyLen);
    if (!isEnc) {
        cr |= CRYP_CR_ALGODIR;
    }
    CRYP->CR = cr;
    CRYP->CR |= CRYP_CR_FFLUSH;
    CRYP->CR |= CRYP_CR_CRYPEN;

    /* For in-place decrypt (out == in) the block loop overwrites the
     * source ciphertext, so the next-IV ciphertext block (the last WHOLE
     * block -- any sub-block remainder is ignored) is captured first. */
    if (!isEnc) {
        XMEMCPY(aes->tmp, in + (blocks - 1) * WC_AES_BLOCK_SIZE,
                WC_AES_BLOCK_SIZE);
    }

    for (b = 0; b < blocks; b++) {
        ret = Stm32AesXferBlock(in  + b * WC_AES_BLOCK_SIZE,
                                out + b * WC_AES_BLOCK_SIZE);
        if (ret != 0) {
            break;
        }
    }

    if (ret == 0) {
        /* Update aes->reg with new IV (last cipher block for enc; saved
         * pre-loop ciphertext for dec). aes.c CBC dispatcher expects
         * aes->reg updated for the next call. */
        if (isEnc) {
            XMEMCPY(aes->reg, out + (blocks - 1) * WC_AES_BLOCK_SIZE,
                    WC_AES_BLOCK_SIZE);
        }
        else {
            XMEMCPY(aes->reg, aes->tmp, WC_AES_BLOCK_SIZE);
        }
    }

exit:
    CRYP->CR &= ~CRYP_CR_CRYPEN;
    wolfSSL_CryptHwMutexUnLock();
    return ret;
}

/* CTR: handled via the ECB-as-transform path in aes.c (XTRANSFORM_AESCTRBLOCK).
 * Each per-block ECB call comes through wc_Stm32_Aes_Ecb above; aes.c manages
 * the counter and the XOR with plaintext. */

/* === HW GCM (CRYP IP phase machine) ==========================================
 * Native HW GCM for the case the CRYP IP supports directly:
 *   - IV is 96 bits (12 bytes) -- the standard GCM IV
 *   - AAD and PT lengths are whole 16-byte blocks (no partial last block)
 * Returns CRYPTOCB_UNAVAILABLE for unsupported parameter combos, so the
 * caller (aes.c BARE GCM dispatcher) falls back to SW GHASH + HW ECB. */
static int Stm32AesXferDiscardOut(const byte* in)
{
    int ret;
    word32 i;
    word32 buf[WC_AES_BLOCK_SIZE/sizeof(word32)];

    XMEMCPY(buf, in, WC_AES_BLOCK_SIZE);
    for (i = 0; i < 4; i++) {
        ret = Stm32AesWaitInNotFull();
        if (ret != 0) {
            return ret;
        }
        CRYP->DIN = buf[i];
    }
    return Stm32AesWaitBusy();
}

/* GCM init phase (GCMPH=00): caller has already written cr_base|phase=0
 * and loaded key/IV. FFLUSH + CRYPEN; wait for CRYPEN to auto-clear
 * (H7-documented mechanism for end-of-init-phase; F4 behaves the same). */
static int Stm32GcmInitPhase(void)
{
    int t;
    CRYP->CR |= CRYP_CR_FFLUSH;
    CRYP->CR |= CRYP_CR_CRYPEN;
    t = 0;
    while ((CRYP->CR & CRYP_CR_CRYPEN) != 0) {
        if (++t >= STM32_BARE_AES_TIMEOUT) return WC_TIMEOUT_E;
    }
    return 0;
}

/* GCM header/AAD phase (GCMPH=01). Whole blocks via DIN (no DOUT
 * read); partial last block padded with zeros -- GHASH math uses
 * aadSz bits in the final phase to truncate correctly. */
static int Stm32GcmAadPhase(const byte* aad, word32 aadSz, word32 cr_base)
{
    word32 b, aadBlocks, aadPartial;
    int ret;

    if (aadSz == 0) return 0;
    aadBlocks  = aadSz / WC_AES_BLOCK_SIZE;
    aadPartial = aadSz % WC_AES_BLOCK_SIZE;

    CRYP->CR = cr_base | (1u << CRYP_CR_GCM_CCMPH_Pos);
    CRYP->CR |= CRYP_CR_CRYPEN;
    for (b = 0; b < aadBlocks; b++) {
        ret = Stm32AesXferDiscardOut(aad + b * WC_AES_BLOCK_SIZE);
        if (ret != 0) return ret;
    }
    if (aadPartial > 0) {
        byte pad[WC_AES_BLOCK_SIZE];
        XMEMSET(pad, 0, sizeof(pad));
        XMEMCPY(pad, aad + aadBlocks * WC_AES_BLOCK_SIZE, aadPartial);
        ret = Stm32AesXferDiscardOut(pad);
        if (ret != 0) return ret;
    }
    ret = Stm32AesWaitBusy();
    if (ret != 0) return ret;
    CRYP->CR &= ~CRYP_CR_CRYPEN;
    return 0;
}

/* GCM payload phase (GCMPH=10). */
static int Stm32GcmPayloadPhase(const byte* in, byte* out, word32 sz,
    word32 cr_base, int isEnc)
{
    word32 b, blocks;
    int ret;

    if (sz == 0) return 0;
    blocks = sz / WC_AES_BLOCK_SIZE;
    CRYP->CR = cr_base | (2u << CRYP_CR_GCM_CCMPH_Pos);
    if (!isEnc) CRYP->CR |= CRYP_CR_ALGODIR;
    CRYP->CR |= CRYP_CR_CRYPEN;
    for (b = 0; b < blocks; b++) {
        ret = Stm32AesXferBlock(in  + b * WC_AES_BLOCK_SIZE,
                                out + b * WC_AES_BLOCK_SIZE);
        if (ret != 0) return ret;
    }
    ret = Stm32AesWaitBusy();
    if (ret != 0) return ret;
    CRYP->CR &= ~CRYP_CR_CRYPEN;
    return 0;
}

/* GCM final phase (GCMPH=11). Feeds 64-bit AAD-bit-len then 64-bit
 * PT-bit-len, then reads 4 DOUT words for the tag.
 *
 * H7 rev.B+ / MP13 (CRYP_VER_2_2): DIN final-phase writes use DATATYPE
 * swap normally -- write plain uint32s.
 *
 * F2/F4/F7 (older CRYP IP, behaves like H7 rev.A): DATATYPE swap does
 * NOT apply to the final-phase length block; SW must pre-swap via
 * __REV. The two HAL families disagree on this and so do their
 * reference drivers -- match each. */
static int Stm32GcmFinalPhase(word32 aadSz, word32 sz, word32 cr_base,
    word32* hwTag)
{
    word32 i;
    int ret;
    word64 aadBits = (word64)aadSz * 8u;
    word64 ptBits  = (word64)sz * 8u;
    word32 aadBitsHi = (word32)(aadBits >> 32);
    word32 aadBitsLo = (word32)aadBits;
    word32 ptBitsHi  = (word32)(ptBits >> 32);
    word32 ptBitsLo  = (word32)ptBits;

#if defined(WOLFSSL_STM32F2) || defined(WOLFSSL_STM32F4) || \
    defined(WOLFSSL_STM32F7)
    aadBitsHi = __REV(aadBitsHi);
    aadBitsLo = __REV(aadBitsLo);
    ptBitsHi  = __REV(ptBitsHi);
    ptBitsLo  = __REV(ptBitsLo);
#endif

    CRYP->CR = cr_base | (3u << CRYP_CR_GCM_CCMPH_Pos);
    CRYP->CR |= CRYP_CR_CRYPEN;

    ret = Stm32AesWaitInNotFull(); if (ret != 0) return ret;
    CRYP->DIN = aadBitsHi;
    ret = Stm32AesWaitInNotFull(); if (ret != 0) return ret;
    CRYP->DIN = aadBitsLo;
    ret = Stm32AesWaitInNotFull(); if (ret != 0) return ret;
    CRYP->DIN = ptBitsHi;
    ret = Stm32AesWaitInNotFull(); if (ret != 0) return ret;
    CRYP->DIN = ptBitsLo;

    for (i = 0; i < 4; i++) {
        ret = Stm32AesWaitOutNotEmpty();
        if (ret != 0) return ret;
        hwTag[i] = CRYP->DOUT;
    }
    return 0;
}

int wc_Stm32_Aes_Gcm(struct Aes* aes, byte* out, const byte* in, word32 sz,
                     const byte* iv, word32 ivSz,
                     byte* tag, word32 tagSz,
                     const byte* aad, word32 aadSz, int isEnc)
{
    int ret;
    word32 keyLen;
    word32 cr_base;
    word32 ivBuf[4];
    word32 hwTag[4];

    if (aes == NULL || iv == NULL || tag == NULL) return BAD_FUNC_ARG;
    if (sz > 0 && (in == NULL || out == NULL)) return BAD_FUNC_ARG;
    if (tagSz < 4u || tagSz > WC_AES_BLOCK_SIZE) return BAD_FUNC_ARG;

    /* HW only supports 12-byte IV (J0 = IV || 0x00000001 form) and whole-
     * block PT (CRYP IP v1 can't natively handle a partial last block).
     * AAD partial is OK -- pad with zeros; GHASH math uses aadSz bits. */
    if (ivSz != GCM_NONCE_MID_SZ) {
    #ifdef DEBUG_STM32_BARE_GCM
        printf("[STM32 BARE GCM] -> SW (ivSz=%u not 12)\n", ivSz);
    #endif
        return CRYPTOCB_UNAVAILABLE;
    }
    if (sz % WC_AES_BLOCK_SIZE != 0) {
    #ifdef DEBUG_STM32_BARE_GCM
        printf("[STM32 BARE GCM] -> SW (sz=%u not whole-block)\n", sz);
    #endif
        return CRYPTOCB_UNAVAILABLE;
    }
#ifdef DEBUG_STM32_BARE_GCM
    printf("[STM32 BARE GCM] -> HW (sz=%u aadSz=%u)\n", sz, aadSz);
#endif

    ret = wc_AesGetKeySize(aes, &keyLen);
    if (ret != 0) return ret;
    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) return ret;
    WC_STM32_AES_CLK_ENABLE();

    /* Set CR (ALGOMODE=AES-GCM, DATATYPE, KEYSIZE, phase=init) BEFORE
     * loading key/IV. H7 reference HAL sets ALGOMODE first then K/IV;
     * the other order on H7 produces a wrong tag even though CT comes
     * out right. */
    cr_base = CRYP_CR_ALGOMODE_AES_GCM | STM32_CRYP_DATATYPE_BYTE |
              Stm32AesKeySizeBits(keyLen);
    CRYP->CR = cr_base | (0u << CRYP_CR_GCM_CCMPH_Pos);

    Stm32AesLoadKey(aes->key, keyLen);

    /* 12-byte IV || counter=0x00000002 (HW pre-increments to 2 for the
     * first payload block; init phase sets up J0). */
    XMEMSET(ivBuf, 0, 16);
    XMEMCPY(ivBuf, iv, 12);
    ((byte*)ivBuf)[15] = 0x02;
    ByteReverseWords(ivBuf, ivBuf, 16);
    CRYP->IV0LR = ivBuf[0]; CRYP->IV0RR = ivBuf[1];
    CRYP->IV1LR = ivBuf[2]; CRYP->IV1RR = ivBuf[3];

    ret = Stm32GcmInitPhase();
    if (ret != 0) goto exit;
    ret = Stm32GcmAadPhase(aad, aadSz, cr_base);
    if (ret != 0) goto exit;
    ret = Stm32GcmPayloadPhase(in, out, sz, cr_base, isEnc);
    if (ret != 0) goto exit;
    ret = Stm32GcmFinalPhase(aadSz, sz, cr_base, hwTag);
    if (ret != 0) goto exit;
    XMEMCPY(tag, hwTag, tagSz < 16 ? tagSz : 16);

exit:
    CRYP->CR &= ~CRYP_CR_CRYPEN;
    wolfSSL_CryptHwMutexUnLock();
    return ret;
}

#else /* TinyAES IP (L4/L5/U5/H5/H573/G0/G4/WB/WL/WBA) */

/* ----- TinyAES IP (single-register, polled) -----
 * Different from CRYP: no FIFO; one DINR / DOUTR pair processed per
 * 16-byte block. KEYRx are written in *reversed* word order
 * (KEYR3 = MSB key word for 128-bit; KEYR7 = MSB for 256-bit).
 * AES-192 not supported by hardware (only 128 and 256). */

#ifndef STM32_BARE_AES_TIMEOUT
    #define STM32_BARE_AES_TIMEOUT 0x10000
#endif

/* CCF (computation-complete) wait/clear, parameterized on the AES
 * instance so the same helpers drive both AES and SAES (DHUK) -- on
 * chips that have both, the IP layout is identical.
 *
 * Clear: newer IPs (U3/U5/L4/L5/H5/G4/WBA/C5) use AES_ICR; older WB/WL/
 * G0 use AES_CR.CCFC; U0 has ICR but it only clears ISR.CCF (we poll
 * SR.CCF on U0), so U0 also uses CR.CCFC. Trailing __DMB() prevents the
 * C5-at-PLL race where the next CCF poll catches an in-flight clear.
 *
 * Wait: C5 polls AES_ISR.CCF; older TinyAES polls AES_SR.CCF; U0 polls
 * SR.CCF (its ISR.CCF only asserts when the matching IER bit is on). */
#if defined(WOLFSSL_STM32U0) && defined(AES_CR_CCFC)
    #define STM32_AES_CLEAR_INST(inst)  do { \
        (inst)->CR |= AES_CR_CCFC; __DMB(); } while (0)
#elif defined(AES_ICR_CCF)
    #define STM32_AES_CLEAR_INST(inst)  do { \
        (inst)->ICR = AES_ICR_CCF; __DMB(); } while (0)
#elif defined(AES_CR_CCFC)
    #define STM32_AES_CLEAR_INST(inst)  do { \
        (inst)->CR |= AES_CR_CCFC; __DMB(); } while (0)
#else
    #error "STM32 AES IP variant: no CCF-clear mechanism known"
#endif

#if defined(WOLFSSL_STM32U0) && defined(AES_SR_CCF)
    #define STM32_AES_CCF_BIT      AES_SR_CCF
    #define STM32_AES_CCF_REG      SR
#elif defined(AES_ISR_CCF)
    #define STM32_AES_CCF_BIT      AES_ISR_CCF
    #define STM32_AES_CCF_REG      ISR
#elif defined(AES_SR_CCF)
    #define STM32_AES_CCF_BIT      AES_SR_CCF
    #define STM32_AES_CCF_REG      SR
#else
    #error "STM32 AES IP variant: no CCF status register known"
#endif

/* Back-compat alias for the unparameterized regular-AES call sites. */
#define STM32_AES_CLEAR_CCF()  STM32_AES_CLEAR_INST(WC_STM32_AES_INST)

#define STM32_AES_DATATYPE_BYTE  AES_CR_DATATYPE_1   /* 0b10 */
#define STM32_AES_CHMOD_ECB      0u
#define STM32_AES_CHMOD_CBC      AES_CR_CHMOD_0
#define STM32_AES_CHMOD_CTR      AES_CR_CHMOD_1
#define STM32_AES_CHMOD_GCM      (AES_CR_CHMOD_0 | AES_CR_CHMOD_1)
#define STM32_AES_MODE_ENC       0u
#define STM32_AES_MODE_KEYDERIVE AES_CR_MODE_0
#define STM32_AES_MODE_DEC       AES_CR_MODE_1
#define STM32_AES_MODE_KD_DEC    (AES_CR_MODE_0 | AES_CR_MODE_1)

/* Poll CCF on either AES instance (regular or SAES). Force prior
 * config / DINR writes to retire before polling -- required on the C5
 * family at PLL clock, where without the barrier the write buffer can
 * defer the last DINR write past the first CCF read, latching us on a
 * stale (still-zero) status. */
static int Stm32AesPollCCF(AES_TypeDef* inst, int timeout)
{
    int t = 0;
    __DMB();
    while ((inst->STM32_AES_CCF_REG & STM32_AES_CCF_BIT) == 0) {
        if (++t >= timeout) {
        #if defined(DEBUG_STM32_BARE_GCM) || defined(WC_STM32_SAES_DIAG)
            printf("[STM32 BARE AES] CCF timeout: CCFreg=0x%08lx CR=0x%08lx "
                   "ISR=0x%08lx SR=0x%08lx\n",
                   (unsigned long)(inst->STM32_AES_CCF_REG),
                   (unsigned long)inst->CR,
                   (unsigned long)inst->ISR,
                   (unsigned long)inst->SR);
        #endif
            return WC_TIMEOUT_E;
        }
    }
    return 0;
}

/* Back-compat wrapper for the regular-AES (`WC_STM32_AES_INST`) call sites.
 * DHUK / SAES call Stm32AesPollCCF(SAES, STM32_BARE_SAES_TIMEOUT) directly. */
static int Stm32AesWaitCCF(void)
{
    return Stm32AesPollCCF(WC_STM32_AES_INST, STM32_BARE_AES_TIMEOUT);
}

static word32 Stm32AesKeySizeBits(word32 keyLen)
{
    if (keyLen == 32) {
        return AES_CR_KEYSIZE; /* 256-bit */
    }
    return 0;                  /* 128-bit (192 not supported by HW) */
}

/* Load a pre-byte-reversed AES key into KEYR0..KEYR(N-1) of `inst`.
 * KEYR(N-1) holds the high word; KEYR0 must be written first per RM.
 * 16-byte (AES-128) and 32-byte (AES-256) keys only -- TinyAES HW does
 * not support AES-192. */
static int Stm32AesLoadKeyInst(AES_TypeDef* inst, const word32* key,
    word32 keyLen)
{
    if (keyLen == 16) {
        inst->KEYR0 = key[3]; inst->KEYR1 = key[2];
        inst->KEYR2 = key[1]; inst->KEYR3 = key[0];
        return 0;
    }
    if (keyLen == 32) {
        inst->KEYR0 = key[7]; inst->KEYR1 = key[6];
        inst->KEYR2 = key[5]; inst->KEYR3 = key[4];
        inst->KEYR4 = key[3]; inst->KEYR5 = key[2];
        inst->KEYR6 = key[1]; inst->KEYR7 = key[0];
        return 0;
    }
    return BAD_FUNC_ARG;
}

static int Stm32AesLoadKey(const word32* key, word32 keyLen)
{
    return Stm32AesLoadKeyInst(WC_STM32_AES_INST, key, keyLen);
}

static void Stm32AesLoadIV(const byte* iv, word32 ivLen)
{
    word32 v[4];
    word32 copyLen = (ivLen > 16) ? 16 : ivLen;

    XMEMSET(v, 0, sizeof(v));
    if (iv != NULL && copyLen > 0) {
        XMEMCPY(v, iv, copyLen);
        ByteReverseWords(v, v, 16);
    }
    /* IVRx ordering matches keyword: IVR3 = MSB */
    WC_STM32_AES_INST->IVR3 = v[0];
    WC_STM32_AES_INST->IVR2 = v[1];
    WC_STM32_AES_INST->IVR1 = v[2];
    WC_STM32_AES_INST->IVR0 = v[3];
}

/* One 16-byte block in / out. */
static int Stm32AesXferBlock(const byte* in, byte* out)
{
    int ret;
    word32 i;
    word32 buf[WC_AES_BLOCK_SIZE/sizeof(word32)];

    XMEMCPY(buf, in, WC_AES_BLOCK_SIZE);
    for (i = 0; i < 4; i++) {
        WC_STM32_AES_INST->DINR = buf[i];
    }
    ret = Stm32AesWaitCCF();
    if (ret != 0) {
        return ret;
    }
    for (i = 0; i < 4; i++) {
        buf[i] = WC_STM32_AES_INST->DOUTR;
    }
    XMEMCPY(out, buf, WC_AES_BLOCK_SIZE);
    /* Clear CCF for next block */
    STM32_AES_CLEAR_CCF();
    return 0;
}

/* Run the key-derivation pass before decrypt (CBC/ECB). */
static int Stm32AesPrepareKey(word32 keyLen, word32 chmod)
{
    int ret;
    word32 cr = STM32_AES_MODE_KEYDERIVE | STM32_AES_DATATYPE_BYTE |
                Stm32AesKeySizeBits(keyLen) | chmod;
    WC_STM32_AES_INST->CR = cr;
    WC_STM32_AES_INST->CR |= AES_CR_EN;
    ret = Stm32AesWaitCCF();
    STM32_AES_CLEAR_CCF();
    WC_STM32_AES_INST->CR &= ~AES_CR_EN;
    return ret;
}

/* Forward decls for the SAES self-init helpers defined further down
 * (inside the WOLFSSL_DHUK || WOLFSSL_STM32_USE_SAES block). Needed
 * because the TinyAES ECB/CBC entry points have to drive the SAES
 * init dance before the first CR write when routed via SAES. */
#ifdef WOLFSSL_STM32_USE_SAES
static int Stm32SaesWaitInit(void);
static void Stm32SaesEnsureRng(void);
#endif

/* Shared setup for TinyAES Ecb/Cbc: clock enable, SAES self-init
 * (when routed), CR=0 / config program, key load, decrypt key-
 * derivation pass. Caller follows up with the IV (Cbc) and the
 * single-write CR | EN to start the data path.
 *
 * SAES quirk: KEYSIZE/MODE/CHMOD are only writable when EN=0 AND
 * BUSY=0, so a Stm32SaesWaitInit() drain is inserted after every
 * write that can leave BUSY set (cold-enable, CR=0 reset, KEYR
 * load). */
static int Stm32AesSetupCR(struct Aes* aes, int isEnc, word32 chmod,
    word32 keyLen, word32* outCr)
{
    int ret;
    word32 cr = STM32_AES_DATATYPE_BYTE | Stm32AesKeySizeBits(keyLen) |
                chmod |
                (isEnc ? STM32_AES_MODE_ENC : STM32_AES_MODE_DEC);

    WC_STM32_AES_CLK_ENABLE_INST();
#ifdef WOLFSSL_STM32_USE_SAES
    Stm32SaesEnsureRng();
    ret = Stm32SaesWaitInit();
    if (ret != 0) return ret;
#endif

    WC_STM32_AES_INST->CR = 0;
#ifdef WOLFSSL_STM32_USE_SAES
    ret = Stm32SaesWaitInit();
    if (ret != 0) return ret;
#endif

    WC_STM32_AES_INST->CR = cr;
    STM32_AES_CLEAR_CCF();

    ret = Stm32AesLoadKey(aes->key, keyLen);
    if (ret != 0) return ret;
#ifdef WOLFSSL_STM32_USE_SAES
    ret = Stm32SaesWaitInit();
    if (ret != 0) return ret;
#endif

    if (!isEnc) {
        WC_STM32_AES_INST->CR = ((cr & ~AES_CR_MODE_Msk) |
            STM32_AES_MODE_KEYDERIVE);
        WC_STM32_AES_INST->CR |= AES_CR_EN;
        ret = Stm32AesWaitCCF();
        STM32_AES_CLEAR_CCF();
        WC_STM32_AES_INST->CR &= ~AES_CR_EN;
        if (ret != 0) return ret;
        WC_STM32_AES_INST->CR = cr;
    }
    *outCr = cr;
    return 0;
}

/* Single-write CR | EN. OR-RMW would lose KEYSIZE/MODE/CHMOD on SAES
 * if BUSY happens to be set when the second write lands. */
static int Stm32AesBlockLoop(const byte* in, byte* out, word32 sz)
{
    word32 blocks = sz / WC_AES_BLOCK_SIZE;
    word32 b;
    int ret = 0;
    for (b = 0; b < blocks; b++) {
        ret = Stm32AesXferBlock(in + b * WC_AES_BLOCK_SIZE,
                                out + b * WC_AES_BLOCK_SIZE);
        if (ret != 0) break;
    }
    return ret;
}

int wc_Stm32_Aes_Ecb(struct Aes* aes, byte* out, const byte* in,
                     word32 sz, int isEnc)
{
    int ret;
    word32 keyLen, cr;

    if (aes == NULL || out == NULL || in == NULL) return BAD_FUNC_ARG;
    if (sz == 0 || (sz % WC_AES_BLOCK_SIZE) != 0) return BAD_FUNC_ARG;
    ret = wc_AesGetKeySize(aes, &keyLen);
    if (ret != 0) return ret;
    if (keyLen != 16 && keyLen != 32) return BAD_FUNC_ARG;

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) return ret;

    ret = Stm32AesSetupCR(aes, isEnc, STM32_AES_CHMOD_ECB, keyLen, &cr);
    if (ret != 0) goto exit;

    WC_STM32_AES_INST->CR = cr | AES_CR_EN;
    ret = Stm32AesBlockLoop(in, out, sz);

exit:
    WC_STM32_AES_INST->CR &= ~AES_CR_EN;
    wolfSSL_CryptHwMutexUnLock();
    return ret;
}

int wc_Stm32_Aes_Cbc(struct Aes* aes, byte* out, const byte* in,
                     word32 sz, int isEnc)
{
    int ret;
    word32 keyLen, cr, blocks;

    if (aes == NULL || out == NULL || in == NULL) return BAD_FUNC_ARG;
    /* Match the CRYP backend + SW/CUBEMX: process whole blocks and ignore any
     * sub-block remainder (the wc_AesCbcEncrypt/Decrypt wrappers reject a
     * non-block-multiple only under WOLFSSL_AES_CBC_LENGTH_CHECKS). */
    blocks = sz / WC_AES_BLOCK_SIZE;
    if (blocks == 0) return 0;
    sz = blocks * WC_AES_BLOCK_SIZE;
    ret = wc_AesGetKeySize(aes, &keyLen);
    if (ret != 0) return ret;
    if (keyLen != 16 && keyLen != 32) return BAD_FUNC_ARG;

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) return ret;

    ret = Stm32AesSetupCR(aes, isEnc, STM32_AES_CHMOD_CBC, keyLen, &cr);
    if (ret != 0) goto exit;

    Stm32AesLoadIV((const byte*)aes->reg, WC_AES_BLOCK_SIZE);
    WC_STM32_AES_INST->CR = cr | AES_CR_EN;

    /* In-place decrypt overwrites the last ciphertext block, so capture
     * it for the next IV before the block loop. */
    if (!isEnc) {
        XMEMCPY(aes->tmp, in + sz - WC_AES_BLOCK_SIZE, WC_AES_BLOCK_SIZE);
    }
    ret = Stm32AesBlockLoop(in, out, sz);
    if (ret == 0) {
        blocks = sz / WC_AES_BLOCK_SIZE;
        if (isEnc) {
            XMEMCPY(aes->reg, out + (blocks - 1) * WC_AES_BLOCK_SIZE,
                    WC_AES_BLOCK_SIZE);
        }
        else {
            XMEMCPY(aes->reg, aes->tmp, WC_AES_BLOCK_SIZE);
        }
    }

exit:
    WC_STM32_AES_INST->CR &= ~AES_CR_EN;
    wolfSSL_CryptHwMutexUnLock();
    return ret;
}

/* TinyAES HW GCM: deferred. Falls back to software GCM (with HW ECB
 * blocks via wc_AesEncrypt -> wc_Stm32_Aes_Ecb). */
int wc_Stm32_Aes_Gcm(struct Aes* aes, byte* out, const byte* in, word32 sz,
                     const byte* iv, word32 ivSz,
                     byte* tag, word32 tagSz,
                     const byte* aad, word32 aadSz, int isEnc)
{
    (void)aes; (void)out; (void)in; (void)sz;
    (void)iv;  (void)ivSz;
    (void)tag; (void)tagSz;
    (void)aad; (void)aadSz; (void)isEnc;
    return CRYPTOCB_UNAVAILABLE;
}

#endif /* CRYP IP vs TinyAES IP */


#if defined(WOLFSSL_DHUK) || defined(WOLFSSL_STM32_USE_SAES)
/* ----- BARE SAES helpers (shared by DHUK and the TinyAES SAES route)
 * Direct-register SAES self-init / RNG enable used by both the DHUK
 * wrap/unwrap path and the TinyAES BARE path when routed to SAES via
 * WOLFSSL_STM32_USE_SAES.
 *
 * SAES on H5/U3/U5/WBA/C5/N6 fetches random data from the RNG on the
 * first clock-enable; SR.BUSY stays set until that init completes and
 * the IP silently rejects any CR/KEYR/IVR writes during that window.
 * The regular AES IP has no such dance, so the TinyAES path that
 * targets WC_STM32_AES_INST = CRYP doesn't need these helpers, but the
 * SAES routing does. */

#ifndef SAES
    #error "WOLFSSL_DHUK / WOLFSSL_STM32_USE_SAES require SAES symbol from \
        CMSIS device header"
#endif

#ifndef STM32_BARE_SAES_TIMEOUT
    #define STM32_BARE_SAES_TIMEOUT 0x10000
#endif

/* SAES self-init: the IP fetches random data from the RNG on first
 * clock-enable. SR.BUSY stays set until init completes. SAES rejects
 * config writes during this window. Must be called once after
 * WC_STM32_SAES_CLK_ENABLE() before touching CR / KEYR / DINR. */
static int Stm32SaesWaitInit(void)
{
    int t = 0;
    __DMB();
    while ((SAES->SR & AES_SR_BUSY) != 0U) {
        if (++t >= STM32_BARE_SAES_TIMEOUT) {
            return WC_TIMEOUT_E;
        }
    }
    return 0;
}

/* Ensure the RNG IP is producing data. SAES init pulls from the
 * RNG, so RNGEN must be set before the SAES clock-enable triggers
 * SAES self-init. wc_GenerateSeed sets RNGEN on its first call,
 * but DHUK / the SAES TinyAES route may run before any RNG consumer. */
static void Stm32SaesEnsureRng(void)
{
#ifdef WC_STM32_RNG_CLK_ENABLE
    WC_STM32_RNG_CLK_ENABLE();
#endif
    if ((RNG->CR & RNG_CR_RNGEN) == 0U) {
        RNG->CR |= RNG_CR_RNGEN;
        __DMB();
    }
#ifdef RCC_CR_SHSION
    /* On STM32U5/U3 the SAES kernel clock is the SHSI (secure HSI). It must
     * be running or the SAES IP never computes -- CCF never asserts and DHUK
     * wrap/unwrap time out (the SAESSEL mux defaults to SHSI, so just enable
     * SHSI and wait for ready). ST configures this in HAL_CRYP_MspInit; the
     * bare-metal path has to do it here. */
    if ((RCC->CR & RCC_CR_SHSION) == 0U) {
        int t = 0;
        RCC->CR |= RCC_CR_SHSION;
        while ((RCC->CR & RCC_CR_SHSIRDY) == 0U) {
            if (++t >= STM32_BARE_SAES_TIMEOUT) {
                break;
            }
        }
        __DMB();
    }
#endif
}

#endif /* WOLFSSL_DHUK || WOLFSSL_STM32_USE_SAES */

#if defined(WOLFSSL_DHUK)
/* BARE DHUK / SAES key wrap+unwrap. Mirrors STM32Cube U5
 * stm32u5xx_hal_cryp_ex.c.
 *   wc_Stm32_Aes_Wrap   -- wrap a plain key for provisioning.
 *   wc_Stm32_Aes_DhukOp -- combined unwrap + ECB enc/dec using the
 *                          wrapped key in aes->key (KMOD=WRAPPED,
 *                          KEYSEL=HW). ECB only for now. */

/* The DHUK code calls Stm32AesPollCCF(SAES, STM32_BARE_SAES_TIMEOUT) and
 * STM32_AES_CLEAR_INST(SAES) directly -- unified with the regular AES
 * path; see the Stm32AesPollCCF / STM32_AES_CLEAR_INST definitions
 * above. */
#define Stm32SaesWaitCCF()   Stm32AesPollCCF(SAES, STM32_BARE_SAES_TIMEOUT)
#define Stm32SaesClearCCF()  STM32_AES_CLEAR_INST(SAES)

/* Run one ECB block through SAES: push the 4-word input (DINR x4), wait
 * for CCF, read the 4-word result (DOUTR x4) back into buf in place, then
 * clear CCF. Returns the Stm32SaesWaitCCF() status; on timeout the DOUTR
 * words are left unread and CCF is not cleared (the caller ForceZero's buf
 * and bails). Centralizes the DINR / CCF / DOUTR idiom shared by the DHUK
 * wrap, GMAC and ECB/CBC paths. */
static int Stm32SaesEcbBlock(word32 buf[4])
{
    int ret;
    SAES->DINR = buf[0];
    SAES->DINR = buf[1];
    SAES->DINR = buf[2];
    SAES->DINR = buf[3];
    ret = Stm32SaesWaitCCF();
    if (ret != 0) {
        return ret;
    }
    buf[0] = SAES->DOUTR;
    buf[1] = SAES->DOUTR;
    buf[2] = SAES->DOUTR;
    buf[3] = SAES->DOUTR;
    Stm32SaesClearCCF();
    return ret;
}

/* Wrap an AES key via SAES. Wrap-key source selected by aes->devId:
 *   WOLFSSL_DHUK_DEVID -- KEYSEL=HW: encrypt under silicon DHUK
 *                         (chip-bound blob); aes->key is ignored.
 *   anything else      -- KEYSEL=NORMAL: encrypt under aes->key
 *                         (loaded into KEYR). */
int wc_Stm32_Aes_Wrap(struct Aes* aes, const byte* in, word32 inSz,
    byte* out, word32* outSz, const byte* iv, int ivSz)
{
    int ret;
    int useDhuk;
    word32 cr;
    word32 i;
    word32 nWords;
    word32 keyLen;
    word32 buf[8]; /* up to 256-bit key */

    if (aes == NULL || in == NULL || out == NULL || outSz == NULL) {
        return BAD_FUNC_ARG;
    }
    if (inSz != 16 && inSz != 32) {
        return BAD_FUNC_ARG;
    }
    if (iv != NULL && ivSz != 16) {
        return BAD_FUNC_ARG;
    }

    useDhuk = (aes->devId == WOLFSSL_DHUK_DEVID);

    /* KEYSIZE and the KEYR load describe the WRAPPING key, not the wrapped
     * payload (inSz). Under KEYSEL = HW the wrapping key is the 256-bit DHUK;
     * otherwise it is aes->key (aes->keylen bytes). */
    if (useDhuk) {
        keyLen = 32;            /* DHUK is 256-bit */
    }
    else {
        keyLen = aes->keylen;
        if (keyLen != 16 && keyLen != 32) {
            return BAD_FUNC_ARG;
        }
    }

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }

    /* RNG must be running before SAES clock-enable -- SAES self-init
     * pulls entropy from the RNG. */
    Stm32SaesEnsureRng();
#ifdef WC_STM32_SAES_CLK_ENABLE
    WC_STM32_SAES_CLK_ENABLE();
#endif

    /* Wait for SAES self-init (SR.BUSY) to clear before configuring. */
    ret = Stm32SaesWaitInit();
    if (ret != 0) {
        wolfSSL_CryptHwMutexUnLock();
        return ret;
    }

    /* Disable SAES before reconfiguring CR (per RM). Clear any stale
     * CCF before we begin. */
    SAES->CR = 0;
    Stm32SaesClearCCF();

    /* CR: byte data type, KMOD = WRAPPED, MODE = ENCRYPT (= 0),
     * CHMOD = ECB (default) or CBC (when IV given), KEYSIZE = 256
     * if 32-byte key. KEYSEL = HW (DHUK) under useDhuk, else NORMAL. */
    cr = AES_CR_DATATYPE_1;             /* 0b10 -- byte */
    cr |= AES_CR_KMOD_0;                /* KMOD = WRAPPED */
    if (useDhuk) {
        cr |= AES_CR_KEYSEL_0;          /* KEYSEL = HW (DHUK) */
    }
    if (keyLen == 32) {
        cr |= AES_CR_KEYSIZE;
    }
    if (iv != NULL) {
        cr |= AES_CR_CHMOD_0;           /* CHMOD = CBC */
    }
    SAES->CR = cr;

    /* Load KEYR only for the software-key path. With KEYSEL = HW the
     * IP reads DHUK directly and ignores KEYR. */
    if (!useDhuk) {
        ret = Stm32AesLoadKeyInst(SAES, (const word32*)aes->key, keyLen);
        if (ret != 0) {
            wolfSSL_CryptHwMutexUnLock();
            return ret;
        }
    }

    if (iv != NULL) {
        /* Alignment-safe IV copy via local buffer (iv is a byte* and
         * may not be 4-byte aligned). IVR{3..0} are written in the
         * same word order the existing TinyAES Stm32AesLoadIv() helper
         * uses (high-significance word -> IVR3, low -> IVR0), and the
         * IV bytes are taken as-is to match the caller's convention. */
        word32 ivWords[4];
        XMEMCPY(ivWords, iv, 16);
        SAES->IVR3 = ivWords[0];
        SAES->IVR2 = ivWords[1];
        SAES->IVR1 = ivWords[2];
        SAES->IVR0 = ivWords[3];
    }
    (void)ivSz;

    /* Stage input. */
    XMEMCPY(buf, in, inSz);

    /* Enable SAES. */
    SAES->CR |= AES_CR_EN;

    /* Process one block (4 words) at a time. 128-bit key = 1 block,
     * 256-bit key = 2 blocks. */
    nWords = inSz / 4u;
    for (i = 0; i < nWords; i += 4u) {
        ret = Stm32SaesEcbBlock(&buf[i]);
        if (ret != 0) {
            goto exit;
        }
    }

    SAES->CR &= ~AES_CR_EN;

    XMEMCPY(out, buf, inSz);
    *outSz = inSz;

exit:
    ForceZero(buf, sizeof(buf));
    wolfSSL_CryptHwMutexUnLock();
    return ret;
}

/* Combined DHUK unwrap + ECB encrypt or decrypt. The caller's aes
 * struct holds the wrapped 256-bit key; SAES unwraps it under the
 * silicon-bound DHUK and runs ECB enc/dec on the input blocks.
 *
 * Default-off: the unwrap-decrypt pass needs secure-state context
 * (TZ-enabled build) -- on the silicon we have on hand (U3, WBA52,
 * both TZEN=0 from factory) the wrapped-key DECRYPT hangs with
 * SR.KEYVALID=1 but CCF never asserts. Wrap is silicon-validated
 * deterministic chip-bound output via wc_Stm32_Aes_Wrap; DhukOp
 * stays gated until a TZ-secure validation lands. Define
 * WOLFSSL_STM32_DHUK_UNWRAP to opt into the experimental path. */
#ifndef WOLFSSL_STM32_DHUK_UNWRAP
int wc_Stm32_Aes_DhukOp_ex(struct Aes* aes, byte* out, const byte* in,
    word32 sz, int isEnc, int isCbc)
{
    (void)aes; (void)out; (void)in; (void)sz; (void)isEnc; (void)isCbc;
    return CRYPTOCB_UNAVAILABLE;
}
#else
int wc_Stm32_Aes_DhukOp_ex(struct Aes* aes, byte* out, const byte* in,
    word32 sz, int isEnc, int isCbc)
{
    int ret;
    word32 cr;
    word32 cr2;
    word32 chmod;
    word32 i;
    word32 blocks;
    word32 wrappedKey[8];
    byte   prevCt[WC_AES_BLOCK_SIZE];

    if (aes == NULL || out == NULL || in == NULL) {
        return BAD_FUNC_ARG;
    }
    if (sz == 0 || (sz % WC_AES_BLOCK_SIZE) != 0) {
        return BAD_FUNC_ARG;
    }
    /* DHUK is 256-bit only. */
    if (aes->keylen != 32) {
        return BAD_FUNC_ARG;
    }
    chmod = isCbc ? STM32_AES_CHMOD_CBC : STM32_AES_CHMOD_ECB;

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }

    Stm32SaesEnsureRng();
#ifdef WC_STM32_SAES_CLK_ENABLE
    WC_STM32_SAES_CLK_ENABLE();
#endif

    /* Wait for SAES self-init (SR.BUSY) before configuring. */
    ret = Stm32SaesWaitInit();
    if (ret != 0) {
        wolfSSL_CryptHwMutexUnLock();
        return ret;
    }

    /* Stage the wrapped key (256-bit) for DINR push. aes->key arrives
     * byte-reversed (BARE convention). */
    XMEMCPY(wrappedKey, aes->key, 32);

    /* Step 1: Unwrap. Mirrors HAL CRYPEx_KeyDecrypt verbatim, using
     * MODIFY_REG-style writes that preserve EN across MODE transitions:
     *
     *   (1a) CR = KMOD=WRAPPED + KEYSEL=HW + KEYSIZE=256 + CHMOD=ECB
     *        + DATATYPE=byte + MODE=KEYDERIVATION. EN=0 initially.
     *   (1b) Set EN. Wait CCF. Clear CCF.
     *   (2a) MODIFY MODE -> DECRYPT, keep EN set.
     *   (2b) Push 8 wrapped key words via DINR in 2 four-word blocks,
     *        wait CCF + clear CCF between blocks. The IP decrypts each
     *        block using DHUK and deposits the unwrapped key into KEYR.
     *   (2c) Clear EN.
     *
     * Earlier attempts that wrote CR=0 between phases (or that skipped
     * the KEYDERIVATION pre-pass) timed out -- SR.KEYVALID asserts but
     * CCF never fires. The HAL approach keeps EN set across MODE
     * changes via MODIFY_REG. */
    Stm32SaesClearCCF();

    /* Step 1a: full CR setup with MODE=KEYDERIVATION, EN=0.
     *
     * On U3 and WBA52 with TZEN=0 and KEYSEL=HW (DHUK), the
     * KEYDERIVATION pass completes but the subsequent DECRYPT pass
     * that deposits the unwrapped key into KEYR does not complete
     * (CCF never asserts; SR.KEYVALID=1; no ISR error). Setting
     * AES_CR_KEYPROT did not help. The wrapped-key-to-KEYR deposit
     * appears to be a secure-state-only operation on this silicon
     * even with TZEN=0. DHUK Wrap (encrypt-with-DHUK) is reachable
     * from NS; DhukOp's unwrap-and-load is not. Documented; caller
     * falls back. */
    cr = AES_CR_DATATYPE_1 | AES_CR_KEYSIZE | AES_CR_KMOD_0 |
         AES_CR_KEYSEL_0 |   /* KEYSEL = HW (DHUK) */
         AES_CR_MODE_0;      /* MODE = KEYDERIVATION */
    SAES->CR = cr;

    /* Step 1b: enable, wait CCF for prep pass, clear CCF. */
    SAES->CR |= AES_CR_EN;
    ret = Stm32SaesWaitCCF();
    if (ret != 0) {
        goto exit;
    }
    Stm32SaesClearCCF();

    /* Step 2a: switch MODE to DECRYPT via MODIFY_REG-style write.
     * Read-modify-write preserves EN and all other bits. */
    cr2 = SAES->CR;
    cr2 = (cr2 & ~AES_CR_MODE) | AES_CR_MODE_1; /* DECRYPT */
    SAES->CR = cr2;

    /* Step 2b: push 8 wrapped-key words via DINR in 2 four-word
     * blocks, wait CCF + clear between. No DOUTR read on unwrap --
     * the result is internally moved to KEYR. */
    for (i = 0; i < 8u; i += 4u) {
        SAES->DINR = wrappedKey[i + 0u];
        SAES->DINR = wrappedKey[i + 1u];
        SAES->DINR = wrappedKey[i + 2u];
        SAES->DINR = wrappedKey[i + 3u];
        ret = Stm32SaesWaitCCF();
        if (ret != 0) {
            goto exit;
        }
        Stm32SaesClearCCF();
    }

    /* Step 2c: disable EN. KEYR now holds the unwrapped key. */
    SAES->CR &= ~AES_CR_EN;
    ForceZero(wrappedKey, sizeof(wrappedKey));

    /* Step 2: ECB/CBC with the unwrapped key now in KEYR. KMOD and
     * KEYSEL go back to NORMAL; decrypt needs a key-derivation prep
     * pass first (last-round-first schedule). CHMOD selects ECB/CBC. */
    cr = AES_CR_DATATYPE_1 | AES_CR_KEYSIZE | chmod; /* KMOD=0, KEYSEL=0 */
    if (!isEnc) {
        SAES->CR = cr | AES_CR_MODE_0;     /* MODE = KEYDERIVATION */
        SAES->CR |= AES_CR_EN;
        ret = Stm32SaesWaitCCF();
        if (ret != 0) {
            goto exit;
        }
        Stm32SaesClearCCF();
        SAES->CR &= ~AES_CR_EN;
        cr |= AES_CR_MODE_1;               /* MODE = DECRYPT */
    }
    SAES->CR = cr;

    /* CBC: load IV from aes->reg into IVR3..IVR0 (MSB first) before
     * setting EN. HW does IV chaining + update. SAES->IVRx direct
     * because WC_STM32_AES_INST may resolve to AES on dual-IP chips. */
    if (chmod == STM32_AES_CHMOD_CBC) {
        word32 v[4];
        XMEMSET(v, 0, sizeof(v));
        XMEMCPY(v, aes->reg, WC_AES_BLOCK_SIZE);
        ByteReverseWords(v, v, 16);
        SAES->IVR3 = v[0];
        SAES->IVR2 = v[1];
        SAES->IVR1 = v[2];
        SAES->IVR0 = v[3];
        ForceZero(v, sizeof(v));
    }

    /* CBC-decrypt: save last input block for next IV before in-place
     * decrypt clobbers it. */
    if (chmod == STM32_AES_CHMOD_CBC && !isEnc) {
        XMEMCPY(prevCt, in + sz - WC_AES_BLOCK_SIZE, WC_AES_BLOCK_SIZE);
    }

    SAES->CR |= AES_CR_EN;

    /* Process input blocks. */
    blocks = sz / WC_AES_BLOCK_SIZE;
    for (i = 0; i < blocks; i++) {
        word32 buf[4];
        word32 j;
        XMEMCPY(buf, in + i * WC_AES_BLOCK_SIZE, WC_AES_BLOCK_SIZE);
        for (j = 0; j < 4u; j++) {
            SAES->DINR = buf[j];
        }
        ret = Stm32SaesWaitCCF();
        if (ret != 0) {
            goto exit;
        }
        for (j = 0; j < 4u; j++) {
            buf[j] = SAES->DOUTR;
        }
        Stm32SaesClearCCF();
        XMEMCPY(out + i * WC_AES_BLOCK_SIZE, buf, WC_AES_BLOCK_SIZE);
    }

    SAES->CR &= ~AES_CR_EN;

    /* CBC: save IV for next call (last ciphertext block). */
    if (chmod == STM32_AES_CHMOD_CBC) {
        if (isEnc) {
            XMEMCPY(aes->reg, out + sz - WC_AES_BLOCK_SIZE,
                    WC_AES_BLOCK_SIZE);
        }
        else {
            XMEMCPY(aes->reg, prevCt, WC_AES_BLOCK_SIZE);
        }
    }

    ret = 0;

exit:
    /* Scrub the in-flight wrapped-key buffer and the SAES key/IV
     * state. After DhukOp the unwrapped key would otherwise be
     * resident in KEYR until the next operation overwrote it; on a
     * platform where a privileged or debug reader can sample the
     * register file, that would defeat the DHUK threat model. Force
     * a hardware reset of the IP via IPRST when the CMSIS exposes
     * it (newer SAES variants); always disable EN and zero our local
     * staging buffer. */
    SAES->CR &= ~AES_CR_EN;
#ifdef AES_CR_IPRST
    SAES->CR |= AES_CR_IPRST;
    __DSB();
    SAES->CR &= ~AES_CR_IPRST;
#endif
    /* CCF clear after IP reset; harmless if IPRST already cleared CCF. */
    Stm32SaesClearCCF();
    ForceZero(wrappedKey, sizeof(wrappedKey));
    ForceZero(prevCt, sizeof(prevCt));
    wolfSSL_CryptHwMutexUnLock();
    return ret;
}
#endif /* WOLFSSL_STM32_DHUK_UNWRAP */

/* Back-compat ECB-only wrapper. */
int wc_Stm32_Aes_DhukOp(struct Aes* aes, byte* out, const byte* in,
    word32 sz, int isEnc)
{
    return wc_Stm32_Aes_DhukOp_ex(aes, out, in, sz, isEnc, 0 /* isCbc */);
}

#if defined(WC_STM32_HAS_DHUK)

#ifdef WOLF_CRYPTO_CB
/* ---- STM32 DHUK SAES backend (driven by the crypto-callback device below) --
 * Derive-from-seed model: a 256-bit seed is mixed with the silicon DHUK so a
 * device-bound working key lands in SAES KEYR; the key never enters SW. The
 * derive and the symmetric op run together under one crypto-mutex hold so KEYR
 * stays valid between them.
 *
 * Validated on STM32U385 (TZEN=0): GMAC is deterministic and round-trip
 * verifies. The key-derivation/decrypt passes complete via SR.BUSY clearing
 * plus SR.KEYVALID, NOT via CCF (CCF is only raised for data-output passes);
 * waiting on CCF for the key path is what previously caused WC_TIMEOUT_E. */

/* AES modes for Stm32Dhuk_Aes (was in the removed dhuk.h). */
#define WC_DHUK_MODE_ECB 0
#define WC_DHUK_MODE_CBC 1

/* The per-key 256-bit seed is NOT held in a shared static -- each operation
 * reads it directly from its own Aes/ecc_key object and derives the working
 * key under the HW crypto mutex (see Stm32SaesDeriveKeyFromSeed, which copies
 * the seed into a ForceZero'd local). This avoids a cross-thread race where a
 * seed staged outside the mutex could be overwritten before it was consumed.
 * DHUK operations are serialized by wolfSSL_CryptHwMutexLock(). */

static int Stm32Dhuk_Init(void* beCtx)
{
    (void)beCtx;
    return 0;
}

static void Stm32Dhuk_Cleanup(void* beCtx)
{
    (void)beCtx;
}

/* Derive a DHUK-bound working key into SAES KEYR from a 256-bit seed.
 * Caller must already hold the crypto mutex and have completed SAES init.
 *   (1) KMOD=WRAPPED, KEYSEL=HW(DHUK), MODE=KEYDERIVATION; enable.
 *   (2) MODE=DECRYPT; re-enable EN (auto-cleared after pass 1); push the seed.
 * Completion of the key-path passes is signalled by SR.BUSY clearing plus
 * SR.KEYVALID, NOT by CCF (CCF is only raised for data-output passes). */
static int Stm32SaesDeriveKeyFromSeed(const byte* seed, word32 seedSz)
{
    word32 seedWords[8];
    word32 i;
    word32 cr;
    word32 spin;
    int    ret = 0;

    if (seed == NULL || seedSz != 32u) {
        return BAD_FUNC_ARG;
    }
    XMEMCPY(seedWords, seed, 32);

    Stm32SaesClearCCF();
    cr = AES_CR_DATATYPE_1 | AES_CR_KEYSIZE | AES_CR_KMOD_0 |
         AES_CR_KEYSEL_0 | AES_CR_MODE_0;   /* MODE = KEYDERIVATION */
    SAES->CR = cr;
    SAES->CR |= AES_CR_EN;
    spin = 0u;
    __DMB();
    while ((SAES->SR & AES_SR_BUSY) != 0u) {
        if (++spin >= (word32)STM32_BARE_SAES_TIMEOUT) {
            ret = WC_TIMEOUT_E;
            goto done;
        }
    }
    Stm32SaesClearCCF();

    cr = (SAES->CR & ~AES_CR_MODE) | AES_CR_MODE_1; /* MODE = DECRYPT */
    SAES->CR = cr;
    SAES->CR |= AES_CR_EN;  /* re-enable (auto-cleared) */
    for (i = 0; i < 8u; i += 4u) {
        SAES->DINR = seedWords[i + 0u];
        SAES->DINR = seedWords[i + 1u];
        SAES->DINR = seedWords[i + 2u];
        SAES->DINR = seedWords[i + 3u];
        spin = 0u;
        __DMB();
        while ((SAES->SR & AES_SR_BUSY) != 0u) {
            if (++spin >= (word32)STM32_BARE_SAES_TIMEOUT) {
                ret = WC_TIMEOUT_E;
                goto done;
            }
        }
        Stm32SaesClearCCF();
    }
    if ((SAES->SR & AES_SR_KEYVALID) == 0u) {
        ret = WC_HW_E;
        goto done;
    }
    SAES->CR &= ~AES_CR_EN;

done:
    ForceZero(seedWords, sizeof(seedWords));
    return ret;
}

/* GMAC tag using a key derived from the staged seed via the silicon DHUK. */
static int Stm32Dhuk_Gmac(const byte* seed, const byte* iv, word32 ivSz,
    const byte* aad, word32 aadSz, byte* tag, word32 tagSz)
{
    /* The Gcm struct (with its GHASH table) is the large object here; move it
     * off the BARE stack onto the heap under WOLFSSL_SMALL_STACK. */
    Gcm*   gcmp;
#ifndef WOLFSSL_SMALL_STACK
    Gcm    gcm_stack;
#endif
    byte   H[WC_AES_BLOCK_SIZE];
    byte   J0[WC_AES_BLOCK_SIZE];
    byte   Ek_J0[WC_AES_BLOCK_SIZE];
    byte   Y[WC_AES_BLOCK_SIZE];
    word32 buf[4];
    word32 i;
    word32 cr;
    int    saes_locked = 0;
    int    ret;

    if (seed == NULL || iv == NULL || tag == NULL) {
        return BAD_FUNC_ARG;
    }
    if (ivSz == 0u) {
        return BAD_FUNC_ARG;
    }
    if (tagSz < 4u || tagSz > WC_AES_BLOCK_SIZE) {
        return BAD_FUNC_ARG;
    }
    if (aad == NULL && aadSz > 0u) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_SMALL_STACK
    gcmp = (Gcm*)XMALLOC(sizeof(*gcmp), NULL, DYNAMIC_TYPE_AES);
    if (gcmp == NULL) {
        return MEMORY_E;
    }
#else
    gcmp = &gcm_stack;
#endif
    XMEMSET(gcmp,  0, sizeof(*gcmp));
    XMEMSET(H,     0, sizeof(H));
    XMEMSET(J0,    0, sizeof(J0));
    XMEMSET(Ek_J0, 0, sizeof(Ek_J0));
    XMEMSET(Y,     0, sizeof(Y));

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        goto exit;
    }
    saes_locked = 1;

    Stm32SaesEnsureRng();
#ifdef WC_STM32_SAES_CLK_ENABLE
    WC_STM32_SAES_CLK_ENABLE();
#endif
    ret = Stm32SaesWaitInit();
    if (ret != 0) {
        goto exit;
    }

    /* Derive the DHUK-bound working key into SAES KEYR from the caller's seed. */
    ret = Stm32SaesDeriveKeyFromSeed(seed, 32u);
    if (ret != 0) {
        goto exit;
    }

    /* ---- ECB-ENCRYPT with the derived key: H = AES_Ek(0), Ek_J0 = AES_Ek(J0);
     * GHASH over AAD in SW; tag = GHASH XOR Ek_J0, truncated. ---- */
    cr = AES_CR_DATATYPE_1 | AES_CR_KEYSIZE; /* KMOD/KEYSEL=NORMAL, ECB */
    SAES->CR = cr;
    SAES->CR |= AES_CR_EN;

    /* H = AES_Ek(0^128) */
    XMEMSET(buf, 0, sizeof(buf));
    ret = Stm32SaesEcbBlock(buf);
    if (ret != 0) {
        ForceZero(buf, sizeof(buf));
        goto exit;
    }
    XMEMCPY(H, buf, WC_AES_BLOCK_SIZE);
    XMEMCPY(gcmp->H, buf, WC_AES_BLOCK_SIZE);
#if defined(GCM_TABLE) || defined(GCM_TABLE_4BIT)
    /* Table-based GHASH multiplies via gcm.M0, not gcm.H, so the table must
     * be built from H before any GHASH call below. GCM_SMALL/GCM_WORD32 use
     * gcm.H directly and do not define GenerateM0. */
    GenerateM0(gcmp);
#endif
    ForceZero(buf, sizeof(buf));

    /* J0: 12-byte IV fast path, else GHASH-J0 per NIST SP 800-38D. */
    if (ivSz == 12u) {
        XMEMCPY(J0, iv, 12);
        J0[12] = 0x00;
        J0[13] = 0x00;
        J0[14] = 0x00;
        J0[15] = 0x01;
    }
    else {
        GHASH(gcmp, NULL, 0, iv, ivSz, J0, WC_AES_BLOCK_SIZE);
    }

    /* Ek_J0 = AES_Ek(J0) */
    XMEMCPY(buf, J0, WC_AES_BLOCK_SIZE);
    ret = Stm32SaesEcbBlock(buf);
    if (ret != 0) {
        ForceZero(buf, sizeof(buf));
        goto exit;
    }
    XMEMCPY(Ek_J0, buf, WC_AES_BLOCK_SIZE);
    ForceZero(buf, sizeof(buf));

    SAES->CR &= ~AES_CR_EN;

    GHASH(gcmp, aad, aadSz, NULL, 0, Y, WC_AES_BLOCK_SIZE);
    for (i = 0; i < WC_AES_BLOCK_SIZE; i++) {
        Y[i] ^= Ek_J0[i];
    }
    XMEMCPY(tag, Y, tagSz);
    ret = 0;

exit:
    SAES->CR &= ~AES_CR_EN;
#ifdef AES_CR_IPRST
    SAES->CR |= AES_CR_IPRST;
    __DSB();
    SAES->CR &= ~AES_CR_IPRST;
#endif
    Stm32SaesClearCCF();
    ForceZero(H,     sizeof(H));
    ForceZero(J0,    sizeof(J0));
    ForceZero(Ek_J0, sizeof(Ek_J0));
    ForceZero(Y,     sizeof(Y));
    ForceZero(gcmp,  sizeof(*gcmp));
    if (saes_locked) {
        wolfSSL_CryptHwMutexUnLock();
    }
#ifdef WOLFSSL_SMALL_STACK
    XFREE(gcmp, NULL, DYNAMIC_TYPE_AES);
#endif
    return ret;
}

/* AES ECB/CBC using a key derived from the staged seed via the silicon DHUK.
 * mode = WC_DHUK_MODE_ECB / _CBC; enc != 0 to encrypt. For CBC, iv is the
 * 16-byte chaining value. The derived key never enters software. */
static int Stm32Dhuk_Aes(const byte* seed, int mode, int enc, const byte* in,
    word32 sz, byte* out, const byte* iv, word32 ivSz)
{
    word32 chmod;
    word32 cr;
    word32 i;
    word32 blocks;
    int    saes_locked = 0;
    int    ret;

    if (seed == NULL || in == NULL || out == NULL) {
        return BAD_FUNC_ARG;
    }
    if (sz == 0u || (sz % WC_AES_BLOCK_SIZE) != 0u) {
        return BAD_FUNC_ARG;
    }
    if (mode == WC_DHUK_MODE_ECB) {
        chmod = STM32_AES_CHMOD_ECB;
    }
    else if (mode == WC_DHUK_MODE_CBC) {
        if (iv == NULL || ivSz != WC_AES_BLOCK_SIZE) {
            return BAD_FUNC_ARG;
        }
        chmod = STM32_AES_CHMOD_CBC;
    }
    else {
        return BAD_FUNC_ARG; /* CTR not supported on this path yet */
    }

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }
    saes_locked = 1;

    Stm32SaesEnsureRng();
#ifdef WC_STM32_SAES_CLK_ENABLE
    WC_STM32_SAES_CLK_ENABLE();
#endif
    ret = Stm32SaesWaitInit();
    if (ret != 0) {
        goto exit;
    }

    ret = Stm32SaesDeriveKeyFromSeed(seed, 32u);
    if (ret != 0) {
        goto exit;
    }

    /* ECB/CBC with the derived key now in KEYR (KMOD=NORMAL, KEYSEL=NORMAL).
     * Decrypt needs a KEYDERIVATION prep pass first (last-round-first key
     * schedule); that prep is a key-path pass -> wait BUSY, not CCF. */
    cr = AES_CR_DATATYPE_1 | AES_CR_KEYSIZE | chmod;
    if (!enc) {
        /* Normal-mode (KMOD=NORMAL) decrypt key-schedule prep: this IS a
         * data/compute pass and raises CCF (unlike the wrapped-key DHUK derive,
         * which signals via BUSY/KEYVALID). Waiting on BUSY here clears too
         * early and yields an incomplete inverse schedule. */
        SAES->CR = cr | AES_CR_MODE_0;     /* MODE = KEYDERIVATION */
        SAES->CR |= AES_CR_EN;
        ret = Stm32SaesWaitCCF();
        if (ret != 0) {
            goto exit;
        }
        Stm32SaesClearCCF();
        SAES->CR &= ~AES_CR_EN;
        cr |= AES_CR_MODE_1;               /* MODE = DECRYPT */
    }
    SAES->CR = cr;

    if (chmod == STM32_AES_CHMOD_CBC) {
        word32 v[4];
        XMEMSET(v, 0, sizeof(v));
        XMEMCPY(v, iv, WC_AES_BLOCK_SIZE);
        ByteReverseWords(v, v, 16);
        SAES->IVR3 = v[0];
        SAES->IVR2 = v[1];
        SAES->IVR1 = v[2];
        SAES->IVR0 = v[3];
        ForceZero(v, sizeof(v));
    }

    SAES->CR |= AES_CR_EN;
    blocks = sz / WC_AES_BLOCK_SIZE;
    for (i = 0; i < blocks; i++) {
        word32 buf[4];
        XMEMCPY(buf, in + i * WC_AES_BLOCK_SIZE, WC_AES_BLOCK_SIZE);
        ret = Stm32SaesEcbBlock(buf);
        if (ret != 0) {
            ForceZero(buf, sizeof(buf));
            goto exit;
        }
        XMEMCPY(out + i * WC_AES_BLOCK_SIZE, buf, WC_AES_BLOCK_SIZE);
        ForceZero(buf, sizeof(buf));
    }
    SAES->CR &= ~AES_CR_EN;
    ret = 0;

exit:
    SAES->CR &= ~AES_CR_EN;
#ifdef AES_CR_IPRST
    SAES->CR |= AES_CR_IPRST;
    __DSB();
    SAES->CR &= ~AES_CR_IPRST;
#endif
    Stm32SaesClearCCF();
    if (saes_locked) {
        wolfSSL_CryptHwMutexUnLock();
    }
    return ret;
}

#if defined(HAVE_ECC) && defined(WOLFSSL_STM32_PKA)
/* Forward declarations: these PKA curve-param converters are defined later in
 * the WOLFSSL_STM32_PKA section of this file. STM32_MAX_ECC_SIZE comes from
 * wolfssl/wolfcrypt/port/st/stm32.h. */
static int stm32_get_from_hexstr(const char* hex, uint8_t* dst, int sz);
static int stm32_getabs_from_hexstr(const char* hex, uint8_t* dst, int sz,
    uint32_t *abs_sign);
static int stm32_get_from_mp_int(uint8_t *dst, const mp_int *a, int sz);

/* Scratch buffers for Stm32Dhuk_Sign, grouped so the whole set (~11 *
 * STM32_MAX_ECC_SIZE bytes) can move off the scarce BARE stack onto the heap
 * under WOLFSSL_SMALL_STACK. */
typedef struct Stm32DhukSignBufs {
    uint8_t Keybin[STM32_MAX_ECC_SIZE];
    uint8_t Intbin[STM32_MAX_ECC_SIZE];
    uint8_t Rbin[STM32_MAX_ECC_SIZE];
    uint8_t Sbin[STM32_MAX_ECC_SIZE];
    uint8_t Hashbin[STM32_MAX_ECC_SIZE];
    uint8_t prime[STM32_MAX_ECC_SIZE];
    uint8_t coefA[STM32_MAX_ECC_SIZE];
#ifdef WOLFSSL_STM32_PKA_V2
    uint8_t coefB[STM32_MAX_ECC_SIZE];
#endif
    uint8_t gen_x[STM32_MAX_ECC_SIZE];
    uint8_t gen_y[STM32_MAX_ECC_SIZE];
    uint8_t order[STM32_MAX_ECC_SIZE];
} Stm32DhukSignBufs;

/* ECDSA sign with a DHUK-protected private key. The staged seed derives an
 * intermediate AES key inside SAES (key never in SW); that key AES-ECB-decrypts
 * the wrapped private scalar (key->dhuk_wrapped_priv) into a short-lived
 * buffer; HAL_PKA_ECDSASign runs; the scalar is ForceZero-scrubbed. Output is a
 * DER-encoded signature (cryptocb EccSign contract). */
static int Stm32Dhuk_Sign(void* beCtx, const struct ecc_key* keyIn,
    const byte* hash, word32 hashLen, byte* sig, word32* sigLen,
    struct WC_RNG* rng)
{
    ecc_key* key = (ecc_key*)keyIn;
    PKA_ECDSASignInTypeDef pka_ecc;
    PKA_ECDSASignOutTypeDef pka_ecc_out;
    mp_int gen_k;
    mp_int order_mp;
    mp_int r;
    mp_int s;
    /* Scratch grouped into *b (heap under WOLFSSL_SMALL_STACK, stack
     * otherwise); the names below alias into it so the body is unchanged. */
    Stm32DhukSignBufs* b;
#ifndef WOLFSSL_SMALL_STACK
    Stm32DhukSignBufs  b_stack;
#endif
    uint8_t *Keybin, *Intbin, *Rbin, *Sbin, *Hashbin, *prime, *coefA;
#ifdef WOLFSSL_STM32_PKA_V2
    uint8_t *coefB;
#endif
    uint8_t *gen_x, *gen_y, *order;
    uint32_t coefA_sign = 1;
    word32 cr;
    word32 i;
    word32 blocks;
    int size;
    int status;
    int saes_locked = 0;

    (void)beCtx;
    XMEMSET(&pka_ecc,     0, sizeof(pka_ecc));
    XMEMSET(&pka_ecc_out, 0, sizeof(pka_ecc_out));

    if (key == NULL || sig == NULL || sigLen == NULL || hash == NULL ||
            rng == NULL || key->dp == NULL) {
        return ECC_BAD_ARG_E;
    }
    if (key->dhuk_seed_sz != 32u) {
        return BAD_FUNC_ARG;
    }
    if (key->dhuk_wrapped_priv_len == 0u ||
        (key->dhuk_wrapped_priv_len % 16u) != 0u ||
        key->dhuk_wrapped_priv_len > (word32)STM32_MAX_ECC_SIZE) {
        return BAD_FUNC_ARG;
    }
    size = wc_ecc_size(key);
    if ((int)key->dhuk_plain_priv_len != size) {
        return BAD_FUNC_ARG;
    }

    /* Early validation done -- allocate the scratch and alias the names. From
     * here on every return goes through the 'cleanup' label so *b is freed. */
#ifdef WOLFSSL_SMALL_STACK
    b = (Stm32DhukSignBufs*)XMALLOC(sizeof(*b), key->heap,
                                    DYNAMIC_TYPE_TMP_BUFFER);
    if (b == NULL) {
        return MEMORY_E;
    }
#else
    b = &b_stack;
#endif
    Keybin  = b->Keybin;  Intbin = b->Intbin; Rbin = b->Rbin; Sbin = b->Sbin;
    Hashbin = b->Hashbin; prime  = b->prime;  coefA = b->coefA;
#ifdef WOLFSSL_STM32_PKA_V2
    coefB = b->coefB;
#endif
    gen_x = b->gen_x; gen_y = b->gen_y; order = b->order;
    XMEMSET(Keybin, 0, STM32_MAX_ECC_SIZE);
    XMEMSET(Intbin, 0, STM32_MAX_ECC_SIZE);

    /* Curve parameters for PKA. */
    status = stm32_get_from_hexstr(key->dp->prime, prime, size);
    if (status == MP_OKAY)
        status = stm32_get_from_hexstr(key->dp->order, order, size);
    if (status == MP_OKAY)
        status = stm32_get_from_hexstr(key->dp->Gx, gen_x, size);
    if (status == MP_OKAY)
        status = stm32_get_from_hexstr(key->dp->Gy, gen_y, size);
    if (status == MP_OKAY)
        status = stm32_getabs_from_hexstr(key->dp->Af, coefA, size,
                                          &coefA_sign);
#ifdef WOLFSSL_STM32_PKA_V2
    if (status == MP_OKAY)
        status = stm32_get_from_hexstr(key->dp->Bf, coefB, size);
#endif
    if (status != MP_OKAY)
        goto cleanup;

    /* Random per-sign "k". */
    mp_init(&gen_k);
    mp_init(&order_mp);
    status = mp_read_unsigned_bin(&order_mp, order, size);
    if (status == MP_OKAY)
        status = wc_ecc_gen_k(rng, size, &gen_k, &order_mp);
    if (status == MP_OKAY)
        status = stm32_get_from_mp_int(Intbin, &gen_k, size);
    mp_clear(&gen_k);
    mp_clear(&order_mp);
    if (status != MP_OKAY) {
        goto cleanup;
    }

    /* ---- SAES: derive intermediate key from the seed, then ECB-DECRYPT the
     * wrapped scalar into Keybin. ---- */
    status = wolfSSL_CryptHwMutexLock();
    if (status != 0) {
        goto cleanup;
    }
    saes_locked = 1;

    Stm32SaesEnsureRng();
#ifdef WC_STM32_SAES_CLK_ENABLE
    WC_STM32_SAES_CLK_ENABLE();
#endif
    status = Stm32SaesWaitInit();
    if (status != 0) {
        goto saes_exit;
    }

    status = Stm32SaesDeriveKeyFromSeed(key->dhuk_seed, key->dhuk_seed_sz);
    if (status != 0) {
        goto saes_exit;
    }

    /* ECB-DECRYPT the wrapped scalar with the derived key in KEYR. The
     * KEYDERIVATION prep is a key-path pass; data blocks use CCF. */
    cr = AES_CR_DATATYPE_1 | AES_CR_KEYSIZE;
    /* Normal-mode decrypt key-schedule prep raises CCF (see do_aes note). */
    SAES->CR = cr | AES_CR_MODE_0;     /* MODE = KEYDERIVATION */
    SAES->CR |= AES_CR_EN;
    status = Stm32SaesWaitCCF();
    if (status != 0) {
        goto saes_exit;
    }
    Stm32SaesClearCCF();
    SAES->CR &= ~AES_CR_EN;
    cr |= AES_CR_MODE_1;               /* MODE = DECRYPT */
    SAES->CR = cr;
    SAES->CR |= AES_CR_EN;

    blocks = key->dhuk_wrapped_priv_len / 16u;
    for (i = 0; i < blocks; i++) {
        word32 buf[4];
        word32 j;
        XMEMCPY(buf, key->dhuk_wrapped_priv + i * 16u, 16u);
        for (j = 0; j < 4u; j++) {
            SAES->DINR = buf[j];
        }
        status = Stm32SaesWaitCCF();
        if (status != 0) {
            ForceZero(buf, sizeof(buf));
            goto saes_exit;
        }
        for (j = 0; j < 4u; j++) {
            buf[j] = SAES->DOUTR;
        }
        Stm32SaesClearCCF();
        XMEMCPY(Keybin + i * 16u, buf, 16u);
        ForceZero(buf, sizeof(buf));
    }
    SAES->CR &= ~AES_CR_EN;
    status = 0;

saes_exit:
    SAES->CR &= ~AES_CR_EN;
#ifdef AES_CR_IPRST
    SAES->CR |= AES_CR_IPRST;
    __DSB();
    SAES->CR &= ~AES_CR_IPRST;
#endif
    Stm32SaesClearCCF();
    if (saes_locked) {
        wolfSSL_CryptHwMutexUnLock();
    }
    if (status != 0) {
        status = (status > 0) ? WC_HW_E : status;
        goto cleanup;
    }

    /* ---- PKA ECDSA sign with the recovered scalar. ---- */
    pka_ecc.primeOrderSize = size;
    pka_ecc.modulusSize    = size;
    pka_ecc.coefSign       = coefA_sign;
    pka_ecc.coef           = coefA;
#ifdef WOLFSSL_STM32_PKA_V2
    pka_ecc.coefB          = coefB;
#endif
    pka_ecc.modulus        = prime;
    pka_ecc.basePointX     = gen_x;
    pka_ecc.basePointY     = gen_y;
    pka_ecc.primeOrder     = order;

    XMEMSET(Hashbin, 0, STM32_MAX_ECC_SIZE);
    if (hashLen > STM32_MAX_ECC_SIZE) {
        status = ECC_BAD_ARG_E;
        goto cleanup;
    }
    else if ((int)hashLen > size) {
        XMEMCPY(Hashbin, hash, size);
    }
    else {
        XMEMCPY(Hashbin + (size - hashLen), hash, hashLen);
    }
    pka_ecc.hash       = Hashbin;
    pka_ecc.integer    = Intbin;
    pka_ecc.privateKey = Keybin;
    pka_ecc_out.RSign  = Rbin;
    pka_ecc_out.SSign  = Sbin;

    status = HAL_PKA_ECDSASign(&hpka, &pka_ecc, HAL_MAX_DELAY);
    if (status != HAL_OK) {
        HAL_PKA_RAMReset(&hpka);
        status = WC_HW_E;
        goto cleanup;
    }
    HAL_PKA_ECDSASign_GetResult(&hpka, &pka_ecc_out, NULL);
    HAL_PKA_RAMReset(&hpka);

    /* DER-encode (r, s) into the caller's signature buffer. */
    mp_init(&r);
    mp_init(&s);
    status = mp_read_unsigned_bin(&r, Rbin, size);
    if (status == MP_OKAY)
        status = mp_read_unsigned_bin(&s, Sbin, size);
    if (status == MP_OKAY)
        status = StoreECC_DSA_Sig(sig, sigLen, &r, &s);
    mp_clear(&r);
    mp_clear(&s);

cleanup:
    /* Scrub the recovered scalar (Keybin) and the random k (Intbin). */
    ForceZero(Keybin, STM32_MAX_ECC_SIZE);
    ForceZero(Intbin, STM32_MAX_ECC_SIZE);
#ifdef WOLFSSL_SMALL_STACK
    XFREE(b, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return status;
}
#endif /* HAVE_ECC && WOLFSSL_STM32_PKA */

/* ---- STM32 DHUK crypto callback -------------------------------------------
 * Flat WOLF_CRYPTO_CB device callback (the established wolfSSL vendor pattern).
 * Enable by setting an object's devId to the registered device at init; supply
 * the 256-bit derivation seed as the normal AES key (wc_AesGcmSetKey/SetKey ->
 * aes->devKey) or, for ECC, via wc_ecc_import_wrapped_private(). The seed never
 * yields a software key: SAES derives the device-bound working key internally
 * from (seed, silicon DHUK). */

#ifndef NO_AES

/* Return the 256-bit seed an Aes carries in devKey (set via the normal key
 * API), or NULL if not a 256-bit seed key. The pointer is valid for the life
 * of the Aes object; the consume path copies it under the HW mutex. */
static const byte* Stm32Dhuk_AesSeed(Aes* aes)
{
    if (aes == NULL || aes->keylen != 32) {
        return NULL;
    }
    return (const byte*)aes->devKey;
}

/* Route a cipher (AES ECB/CBC, AES-GCM/GMAC) request to the SAES backend. */
static int Stm32Dhuk_Cipher(struct wc_CryptoInfo* info)
{
    const byte* seed;
    int ret;

    switch (info->cipher.type) {
#if defined(HAVE_AES_ECB) || defined(WOLFSSL_AES_DIRECT) || \
    defined(WOLF_CRYPTO_CB_ONLY_AES)
    case WC_CIPHER_AES_ECB:
        seed = Stm32Dhuk_AesSeed(info->cipher.aesecb.aes);
        if (seed == NULL) {
            return CRYPTOCB_UNAVAILABLE;
        }
        return Stm32Dhuk_Aes(seed, WC_DHUK_MODE_ECB, info->cipher.enc,
                             info->cipher.aesecb.in, info->cipher.aesecb.sz,
                             info->cipher.aesecb.out, NULL, 0);
#endif
#if defined(HAVE_AES_CBC)
    case WC_CIPHER_AES_CBC:
        /* Transparent DHUK AES is ECB/GCM only. The STM32 BARE/CUBEMX
         * wc_AesCbcEncrypt/Decrypt are the public CBC entry points and do not
         * dispatch through the crypto callback, so this case is not reached in
         * a real DHUK build; wc_AesCbcEncrypt rejects a DHUK devId directly.
         * Fail loud here as defense-in-depth: returning CRYPTOCB_UNAVAILABLE
         * would let the SW CBC fallback run with the seed (aes->key) as the AES
         * key -- a non-device-bound, wrong-key result. */
        (void)ret;
        return NOT_COMPILED_IN;
#endif
#ifdef HAVE_AESGCM
    case WC_CIPHER_AES_GCM:
        /* GMAC = AES-GCM with empty plaintext. Full GCM payload encryption is
         * a follow-on (needs a CTR + GHASH path). For a DHUK key we must NOT
         * fall back to SW GCM: the SW path would key off aes->key, which holds
         * the derivation seed (not the SAES-derived device key), producing a
         * non-device-bound result. Fail loudly instead of returning
         * CRYPTOCB_UNAVAILABLE (which would trigger the SW fallback). */
        if (info->cipher.enc) {
            if (info->cipher.aesgcm_enc.sz != 0) {
                return NOT_COMPILED_IN;
            }
            seed = Stm32Dhuk_AesSeed(info->cipher.aesgcm_enc.aes);
            if (seed == NULL) {
                return CRYPTOCB_UNAVAILABLE;
            }
            return Stm32Dhuk_Gmac(seed,
                                  info->cipher.aesgcm_enc.iv,
                                  info->cipher.aesgcm_enc.ivSz,
                                  info->cipher.aesgcm_enc.authIn,
                                  info->cipher.aesgcm_enc.authInSz,
                                  info->cipher.aesgcm_enc.authTag,
                                  info->cipher.aesgcm_enc.authTagSz);
        }
        else {
            byte   tag[WC_AES_BLOCK_SIZE];
            word32 tagSz = info->cipher.aesgcm_dec.authTagSz;
            /* See enc note: do not fall back to SW GCM for a DHUK key. */
            if (info->cipher.aesgcm_dec.sz != 0) {
                return NOT_COMPILED_IN;
            }
            if (tagSz == 0 || tagSz > sizeof(tag)) {
                return BAD_FUNC_ARG;
            }
            seed = Stm32Dhuk_AesSeed(info->cipher.aesgcm_dec.aes);
            if (seed == NULL) {
                return CRYPTOCB_UNAVAILABLE;
            }
            XMEMSET(tag, 0, sizeof(tag));
            ret = Stm32Dhuk_Gmac(seed,
                                 info->cipher.aesgcm_dec.iv,
                                 info->cipher.aesgcm_dec.ivSz,
                                 info->cipher.aesgcm_dec.authIn,
                                 info->cipher.aesgcm_dec.authInSz,
                                 tag, tagSz);
            if (ret != 0) {
                ForceZero(tag, sizeof(tag));
                return ret;
            }
            /* Constant-time tag compare (0 == equal); ConstantCompare avoids a
             * local re-implementation of the secret compare. */
            ret = ConstantCompare(tag, info->cipher.aesgcm_dec.authTag,
                                  (int)tagSz);
            ForceZero(tag, sizeof(tag));
            return (ret == 0) ? 0 : AES_GCM_AUTH_E;
        }
#endif
    default:
        return CRYPTOCB_UNAVAILABLE;
    }
}
#endif /* !NO_AES */

#if defined(HAVE_ECC) && defined(HAVE_ECC_SIGN) && defined(WOLFSSL_STM32_PKA)
/* Route an ECDSA sign request to the SAES/PKA backend. */
static int Stm32Dhuk_PkSign(struct wc_CryptoInfo* info)
{
    ecc_key* key = info->pk.eccsign.key;

    if (key == NULL) {
        return CRYPTOCB_UNAVAILABLE;
    }
#ifdef WOLFSSL_STM32_CCB
    /* CCB-protected key: the scalar is unwrapped SAES->PKA in hardware and the
     * signature returned as raw (r,s); encode it as the DER ECDSA-Sig output. */
    if (key->dhuk_is_ccb) {
        byte   r[MAX_ECC_BYTES];
        byte   s[MAX_ECC_BYTES];
        word32 sz = (word32)wc_ecc_size(key);
        int    ret;

        ret = wc_Stm32_Ccb_EccSign(ECC_SECP256R1, key->ccb_iv, key->ccb_tag,
                                   key->dhuk_wrapped_priv,
                                   key->dhuk_wrapped_priv_len,
                                   info->pk.eccsign.in, info->pk.eccsign.inlen,
                                   r, s);
        if (ret == 0) {
            ret = wc_ecc_rs_raw_to_sig(r, sz, s, sz,
                                       info->pk.eccsign.out,
                                       info->pk.eccsign.outlen);
        }
        ForceZero(r, sizeof(r));
        ForceZero(s, sizeof(s));
        return ret;
    }
#endif
    if (key->dhuk_seed_sz != 32u) {
        return CRYPTOCB_UNAVAILABLE;
    }
    /* Stm32Dhuk_Sign reads key->dhuk_seed directly under the HW mutex. */
    return Stm32Dhuk_Sign(NULL, key,
                          info->pk.eccsign.in, info->pk.eccsign.inlen,
                          info->pk.eccsign.out, info->pk.eccsign.outlen,
                          info->pk.eccsign.rng);
}
#endif /* HAVE_ECC && HAVE_ECC_SIGN && WOLFSSL_STM32_PKA */

/* The crypto-callback device entry point (registered by wc_Stm32_DhukRegister).
 * Returns CRYPTOCB_UNAVAILABLE for anything it does not handle so the caller
 * falls back to software. */
static int Stm32_CryptoDevCb(int devId, struct wc_CryptoInfo* info, void* ctx)
{
    (void)devId;
    (void)ctx;
    if (info == NULL) {
        return CRYPTOCB_UNAVAILABLE;
    }

    switch (info->algo_type) {
#ifndef NO_AES
        case WC_ALGO_TYPE_CIPHER:
            return Stm32Dhuk_Cipher(info);
#endif
#if defined(HAVE_ECC) && defined(HAVE_ECC_SIGN) && defined(WOLFSSL_STM32_PKA)
        case WC_ALGO_TYPE_PK:
            if (info->pk.type == WC_PK_TYPE_ECDSA_SIGN) {
                return Stm32Dhuk_PkSign(info);
            }
#ifdef WOLFSSL_STM32_CCB
            /* Transparent provisioning: wc_ecc_make_key() on a WC_DHUK_DEVID
             * key binds a fresh CCB-protected blob to it (no CCB-specific API). */
            if (info->pk.type == WC_PK_TYPE_EC_KEYGEN) {
                return wc_ecc_dev_make_key(info->pk.eckg.rng,
                    info->pk.eckg.size, info->pk.eckg.key,
                    info->pk.eckg.curveId);
            }
#endif
            return CRYPTOCB_UNAVAILABLE;
#endif
        default:
            return CRYPTOCB_UNAVAILABLE;
    }
}

/* Register the STM32 DHUK device at devId (e.g. WC_DHUK_DEVID). After this,
 * objects whose devId is set to it at init route transparently to SAES. */
int wc_Stm32_DhukRegister(int devId)
{
    int ret = Stm32Dhuk_Init(NULL);
    if (ret != 0) {
        return ret;
    }
    return wc_CryptoCb_RegisterDevice(devId, Stm32_CryptoDevCb, NULL);
}

void wc_Stm32_DhukUnRegister(int devId)
{
    wc_CryptoCb_UnRegisterDevice(devId);
    Stm32Dhuk_Cleanup(NULL);
}
#endif /* WOLF_CRYPTO_CB */

#ifdef WOLFSSL_STM32_CCB
/* ---------------------------------------------------------------------------
 * CCB (Coupling and Chaining Bridge) -- STM32U3 (e.g. U385, RM0487 ch 31) and
 * STM32C5 (e.g. C5A3, RM0522). The CCB chains PKA <-> SAES <-> RNG over a local
 * interconnect so a DHUK-protected private key is used by the PKA without ever
 * entering software or crossing the system bus.
 * ------------------------------------------------------------------------- */

/* Bound for CCB BUSY / OPSTEP polling (loop iterations). */
#ifndef WC_STM32_CCB_TIMEOUT
    #define WC_STM32_CCB_TIMEOUT 1000000u
#endif

/* PKA RAM as 32-bit words. STM32C5 types PKA->RAM as uint8_t[] -- byte access
 * bus-faults, word access is required; U3 types it as uint32_t[]. Cast to a
 * 32-bit word pointer so the slot indices below address the RAM correctly on
 * both families (mirrors wc_stm32_pka_prep_ram in the standalone PKA path). */
#define WC_CCB_PKA_RAMW   ((volatile uint32_t*)(void*)PKA->RAM)


/* Initialize the CCB peripheral per RM0487 31.5.1: enable the RNG / PKA / SAES
 * / CCB clocks, pulse CCB_CR.IPRST and wait for CCB_SR.BUSY to clear, then
 * confirm no operation error (CCB_SR.OPERR) latched. GTZC is left at its reset
 * configuration -- ST's CCB MspInit configures no GTZC and runs from the
 * non-secure alias, so the TZEN=0 build uses the same. */
static int Stm32Ccb_Init(void)
{
    word32 t;
    word32 operr;

    /* Clocks for every peer the CCB chains (RM 31.5.1 steps 2-5). */
#ifdef WC_STM32_PKA_CLK_ENABLE
    WC_STM32_PKA_CLK_ENABLE();
#endif
#ifdef WC_STM32_SAES_CLK_ENABLE
    WC_STM32_SAES_CLK_ENABLE();
#endif
#ifdef WC_STM32_RNG_CLK_ENABLE
    WC_STM32_RNG_CLK_ENABLE();
#endif
#ifdef WC_STM32_CCB_CLK_ENABLE
    WC_STM32_CCB_CLK_ENABLE();
#endif
#ifdef WC_STM32_CCB_RST_PKA
    /* Reset PKA / SAES / RNG so the CCB starts from a clean peripheral state.
     * Prior standalone use of an engine -- wc_InitRng seeding the RNG, ECC
     * keygen using the PKA -- can leave it in a mode that stalls the CCB's
     * chained SAES GCM step (CCF never asserts, the create phase times out).
     * A prior CCB op masks the problem by leaving the engines CCB-configured,
     * so without this reset the very first CCB op after other crypto fails.
     * Register names are family-abstracted (WC_STM32_CCB_RSTR/RST_*). */
    RCC->WC_STM32_CCB_RSTR |= (WC_STM32_CCB_RST_PKA | WC_STM32_CCB_RST_SAES |
                               WC_STM32_CCB_RST_RNG);
    __DSB();
    RCC->WC_STM32_CCB_RSTR &= ~(WC_STM32_CCB_RST_PKA | WC_STM32_CCB_RST_SAES |
                                WC_STM32_CCB_RST_RNG);
    __DSB();
#endif
#ifdef RCC_CR_SHSION
    /* The SAES kernel clock is the SHSI (secure HSI); the CCB drives the SAES
     * to unwrap the DHUK blob, so SHSI must be running or the SAES never
     * computes -- CCF stalls and the GCM steps time out. The SAESSEL mux
     * defaults to SHSI, so just enable it and wait for ready (ST does this in
     * HAL_CRYP_MspInit). Without this the CCB only works if some prior SAES op
     * happened to turn SHSI on. */
    if ((RCC->CR & RCC_CR_SHSION) == 0U) {
        t = 0;
        RCC->CR |= RCC_CR_SHSION;
        while ((RCC->CR & RCC_CR_SHSIRDY) == 0U) {
            if (++t >= WC_STM32_CCB_TIMEOUT) {
                break;
            }
        }
        __DMB();
    }
#endif

    /* Reset the CCB: set IPRST, wait while BUSY, then clear IPRST. */
    CCB->CR |= CCB_CR_IPRST;
    __DSB();
    t = 0;
    while ((CCB->SR & WC_STM32_CCB_SR_BUSY) != 0u) {
        if (++t >= WC_STM32_CCB_TIMEOUT) {
            CCB->CR &= ~CCB_CR_IPRST;
            return WC_TIMEOUT_E;
        }
    }
    CCB->CR &= ~CCB_CR_IPRST;

    /* Nothing is running yet, so no operation error should be latched. */
    operr = (CCB->SR & CCB_SR_OPERR) >> CCB_SR_OPERR_Pos;
    if (operr != 0u) {
        return WC_HW_E;
    }
    return 0;
}

/* Public M0 entry: bring up the CCB and report whether it is usable. Returns 0
 * on success, WC_TIMEOUT_E if BUSY never clears, WC_HW_E if OPERR latched. */
int wc_Stm32_CcbInit(void)
{
    int ret;

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }
    ret = Stm32Ccb_Init();
    wolfSSL_CryptHwMutexUnLock();
    return ret;
}

/* ---- Bare-metal CCB ECDSA OPSTEP driver (ported from RM0487 ch31 / ST
 * HAL_CCB). The CCB couples PKA RAM writes to the SAES (GCM) so the wrapped
 * scalar is decrypted SAES->PKA over the local bus and never enters software.
 * Reuses the bare PKA helpers (wc_stm32_pka_load_param_be / _read_be) and the
 * SAES CCF macros. Currently P-256 (ECC_SECP256R1). ---- */

/* CCB operation / PKA-mode / magic constants (RM0487, ST hal_ccb). */
#define WC_CCB_OP_SIGN_USE      0x000000C3u  /* CCOP: ECDSA blob-use sign */
#define WC_CCB_OP_CREATE        0x000000C0u  /* CCOP: ECDSA CPU blob create */
#define WC_CCB_OP_SCALAR_USE    0x00000081u  /* CCOP: scalar mul (pubkey) */
#define WC_CCB_PKA_SIGN_MODE    0x24u        /* PKA_CR.MODE for ECDSA sign */
#define WC_CCB_PKA_MUL_MODE     0x20u        /* PKA_CR.MODE for ECC scalar mul */
#define WC_CCB_MAGIC            0x0CCBu      /* SAES->PKA chaining magic */
#define WC_CCB_FAKE             0x0001u      /* placeholder fed to RNG->PKA */
#define WC_CCB_PKA_OK           0x0000D60Du  /* PKA_ECDSA_SIGN_OUT_ERROR ok */

/* P-256 CCB operand sizing. opsz = PKA operand words = 2*(ceil(32/8)+1) = 10;
 * cipsz = SAES ciphertext block count = opsz minus the 2-word PKA pad when
 * opsz is not a multiple of 4 = 8. (Single-curve P-256 today.) */
#define WC_CCB_P256_OPSZ        10u
#define WC_CCB_P256_CIPSZ        8u
/* SAES GCM final-phase header length word for the blob (bit-length encoding). */
#define WC_CCB_GCM_HDR_LEN(opsz) (((((opsz) * 32u) * 6u) + (3u * 64u)) * 2u)

/* NIST P-256 parameters (big-endian, 32 bytes). */
static const byte wc_ccb_p256_aAbs[32] = {
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x03};
static const byte wc_ccb_p256_b[32] = {
    0x5a,0xc6,0x35,0xd8,0xaa,0x3a,0x93,0xe7,0xb3,0xeb,0xbd,0x55,0x76,0x98,0x86,0xbc,
    0x65,0x1d,0x06,0xb0,0xcc,0x53,0xb0,0xf6,0x3b,0xce,0x3c,0x3e,0x27,0xd2,0x60,0x4b};
static const byte wc_ccb_p256_p[32] = {
    0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
static const byte wc_ccb_p256_n[32] = {
    0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xbc,0xe6,0xfa,0xad,0xa7,0x17,0x9e,0x84,0xf3,0xb9,0xca,0xc2,0xfc,0x63,0x25,0x51};
static const byte wc_ccb_p256_Gx[32] = {
    0x6b,0x17,0xd1,0xf2,0xe1,0x2c,0x42,0x47,0xf8,0xbc,0xe6,0xe5,0x63,0xa4,0x40,0xf2,
    0x77,0x03,0x7d,0x81,0x2d,0xeb,0x33,0xa0,0xf4,0xa1,0x39,0x45,0xd8,0x98,0xc2,0x96};
static const byte wc_ccb_p256_Gy[32] = {
    0x4f,0xe3,0x42,0xe2,0xfe,0x1a,0x7f,0x9b,0x8e,0xe7,0xeb,0x4a,0x7c,0x0f,0x9e,0x16,
    0x2b,0xce,0x33,0x57,0x6b,0x31,0x5e,0xce,0xcb,0xb6,0x40,0x68,0x37,0xbf,0x51,0xf5};

/* Wait until CCB_SR.OPSTEP reaches the given step value. */
static int Stm32Ccb_WaitOpStep(word32 step)
{
    word32 t = 0;
    while ((CCB->SR & step) != step) {
        if (++t >= WC_STM32_CCB_TIMEOUT) {
            return WC_TIMEOUT_E;
        }
    }
    return 0;
}

/* Wait for a PKA_SR flag, then clear it via PKA_CLRFR (matches ST). */
static int Stm32Ccb_PkaWaitFlag(word32 flag)
{
    word32 t = 0;
    while ((PKA->SR & flag) == 0u) {
        if (++t >= WC_STM32_CCB_TIMEOUT) {
            return WC_TIMEOUT_E;
        }
    }
    PKA->CLRFR = flag;
    return 0;
}

/* Wait for the SAES CCF (GCM step done), then clear it. */
static int Stm32Ccb_SaesWaitCcf(void)
{
    word32 t = 0;
    while ((SAES->ISR & AES_ISR_CCF) == 0u) {
        if (++t >= WC_STM32_CCB_TIMEOUT) {
            return WC_TIMEOUT_E;
        }
    }
    STM32_AES_CLEAR_INST(SAES);
    return 0;
}

/* Initialize the RNG for CCB use. The U3 RNG only produces DRDY once a
 * NIST-compliant config has been written under CONDRST (same as wc_GenerateSeed
 * in random.c). Always (re)write it here so prior RNG use -- e.g. wc_InitRng
 * leaving a different config -- cannot stall the CCB's RNG->PKA draws. */
static int Stm32Ccb_RngInit(void)
{
    word32 t = 0;
#if defined(RNG_CAND_NIST_CR_VALUE) && defined(RNG_CR_CONDRST)
    RNG->CR = (word32)RNG_CAND_NIST_CR_VALUE | (word32)RNG_CR_CONDRST;
#ifdef RNG_CAND_NIST_NSCR_VALUE
    RNG->NSCR = (word32)RNG_CAND_NIST_NSCR_VALUE;
#endif
#ifdef RNG_CAND_NIST_HTCR_VALUE
    RNG->HTCR[0] = (word32)RNG_CAND_NIST_HTCR_VALUE;
#endif
    RNG->CR &= ~(word32)RNG_CR_CONDRST;   /* latch config */
    while ((RNG->CR & RNG_CR_CONDRST) != 0u) {
        if (++t >= WC_STM32_CCB_TIMEOUT) {
            return WC_TIMEOUT_E;
        }
    }
    RNG->CR |= RNG_CR_RNGEN;
#else
    RNG->CR = RNG_CR_CONDRST;
    RNG->CR = 0u;
    while ((RNG->CR & RNG_CR_CONDRST) != 0u) {
        if (++t >= WC_STM32_CCB_TIMEOUT) {
            return WC_TIMEOUT_E;
        }
    }
    RNG->CR = RNG_CR_RNGEN;
#endif
    if ((RNG->SR & RNG_SR_SEIS) != 0u) {
        return WC_HW_E;
    }
    t = 0;
    while ((RNG->SR & RNG_SR_DRDY) == 0u) {
        if (++t >= WC_STM32_CCB_TIMEOUT) {
            return WC_TIMEOUT_E;
        }
    }
    return 0;
}

/* Enable PKA and set the given protected mode (no interrupts). */
static int Stm32Ccb_PkaInit(word32 mode)
{
    int ret;
    PKA->CR = PKA_CR_EN;
    ret = Stm32Ccb_PkaWaitFlag(PKA_SR_INITOK);
    if (ret != 0) {
        return ret;
    }
    PKA->CLRFR = PKA_CLRFR_PROCENDFC | PKA_CLRFR_RAMERRFC |
                 PKA_CLRFR_ADDRERRFC | PKA_CLRFR_OPERRFC;
    PKA->CR = (PKA->CR & ~(PKA_CR_MODE | PKA_CR_PROCENDIE | PKA_CR_RAMERRIE |
                           PKA_CR_ADDRERRIE | PKA_CR_OPERRIE)) |
              (mode << PKA_CR_MODE_Pos);
    return 0;
}

/* Optimal bit length of a big-endian operand (ST GetOptBitSize_u8). */
static word32 Stm32Ccb_OptBits(word32 nbytes, byte msb)
{
    return ((nbytes - 1u) * 8u) + (32u - (word32)__CLZ((word32)msb));
}

/* Write a small scalar (value + zero word) into PKA RAM, coupled: wait CCF. */
static int Stm32Ccb_SetScalar(word32 slot, word32 val)
{
    WC_CCB_PKA_RAMW[slot]      = val;
    WC_CCB_PKA_RAMW[slot + 1u] = 0u;
    return Stm32Ccb_SaesWaitCcf();
}

/* Write a 32-byte (multiple-of-8) big-endian param into PKA RAM 64 bits at a
 * time, waiting for the SAES CCF coupling after each pair and the terminator
 * (per ST CCB_SetPram during the GCM header phase). */
static int Stm32Ccb_SetParam(word32 slot, const byte* src, word32 sizeBytes)
{
    word32 operand = 2u * (((sizeBytes + 7u) / 8u) + 1u);
    word32 off;
    const byte* p;
    int ret;

    /* The big-endian 8-byte chunk loop walks src[] downward in 8-byte steps;
     * a zero or non-multiple-of-8 sizeBytes would index below src[0] and
     * mis-place the operand window. All callers pass a 32-byte field. */
    if (sizeBytes == 0u || (sizeBytes % 8u) != 0u) {
        return BAD_FUNC_ARG;
    }

    for (off = 0u; off < (operand - 2u); off += 2u) {
        p = &src[sizeBytes - ((off * 4u) + 1u)];
        WC_CCB_PKA_RAMW[slot + off]      = (word32)p[0] | ((word32)p[-1] << 8) |
                                    ((word32)p[-2] << 16) | ((word32)p[-3] << 24);
        WC_CCB_PKA_RAMW[slot + off + 1u] = (word32)p[-4] | ((word32)p[-5] << 8) |
                                    ((word32)p[-6] << 16) | ((word32)p[-7] << 24);
        ret = Stm32Ccb_SaesWaitCcf();
        if (ret != 0) {
            return ret;
        }
    }
    WC_CCB_PKA_RAMW[slot + ((sizeBytes + 3u) / 4u)]      = 0u;
    WC_CCB_PKA_RAMW[slot + ((sizeBytes + 3u) / 4u) + 1u] = 0u;
    return Stm32Ccb_SaesWaitCcf();
}

/* CCB teardown: pulse CCB_CR.IPRST and wait BUSY clear. */
static void Stm32Ccb_Reset(void)
{
    word32 t = 0;
    CCB->CR |= CCB_CR_IPRST;
    __DSB();
    while ((CCB->SR & WC_STM32_CCB_SR_BUSY) != 0u) {
        if (++t >= WC_STM32_CCB_TIMEOUT) {
            break;
        }
    }
    CCB->CR &= ~CCB_CR_IPRST;
}

/* Write 8 big-endian bytes ending at p (p[0]..p[-7]) as two little-endian PKA
 * words at slot -- the 64-bit chunk primitive used for the d / param loads. */
static void Stm32Ccb_Wr64(word32 slot, const byte* p)
{
    WC_CCB_PKA_RAMW[slot]      = (word32)p[0] | ((word32)p[-1] << 8) |
                          ((word32)p[-2] << 16) | ((word32)p[-3] << 24);
    WC_CCB_PKA_RAMW[slot + 1u] = (word32)p[-4] | ((word32)p[-5] << 8) |
                          ((word32)p[-6] << 16) | ((word32)p[-7] << 24);
}

/* Load the ECDSA curve params into PKA RAM, each coupled to the SAES GCM header
 * (wait CCF). Shared by the bare create and sign paths. */
static int Stm32Ccb_LoadCurve(void)
{
    int ret;
    if ((ret = Stm32Ccb_SetScalar(PKA_ECDSA_SIGN_IN_ORDER_NB_BITS,
            Stm32Ccb_OptBits(32u, wc_ccb_p256_n[0]))) != 0) { return ret; }
    if ((ret = Stm32Ccb_SetScalar(PKA_ECDSA_SIGN_IN_MOD_NB_BITS,
            Stm32Ccb_OptBits(32u, wc_ccb_p256_p[0]))) != 0) { return ret; }
    if ((ret = Stm32Ccb_SetScalar(PKA_ECDSA_SIGN_IN_A_COEFF_SIGN, 1u)) != 0)
        { return ret; }
    if ((ret = Stm32Ccb_SetParam(PKA_ECDSA_SIGN_IN_A_COEFF, wc_ccb_p256_aAbs,
            32u)) != 0) { return ret; }
    if ((ret = Stm32Ccb_SetParam(PKA_ECDSA_SIGN_IN_B_COEFF, wc_ccb_p256_b,
            32u)) != 0) { return ret; }
    if ((ret = Stm32Ccb_SetParam(PKA_ECDSA_SIGN_IN_MOD_GF, wc_ccb_p256_p,
            32u)) != 0) { return ret; }
    if ((ret = Stm32Ccb_SetParam(PKA_ECDSA_SIGN_IN_ORDER_N, wc_ccb_p256_n,
            32u)) != 0) { return ret; }
    if ((ret = Stm32Ccb_SetParam(PKA_ECDSA_SIGN_IN_INITIAL_POINT_X,
            wc_ccb_p256_Gx, 32u)) != 0) { return ret; }
    return Stm32Ccb_SetParam(PKA_ECDSA_SIGN_IN_INITIAL_POINT_Y,
            wc_ccb_p256_Gy, 32u);
}

/* Wait until a SAES_SR flag reaches the wanted state (used for BUSY/KEYVALID). */
static int Stm32Ccb_SaesWaitSr(word32 flag, int wantSet)
{
    word32 t = 0;
    while (((SAES->SR & flag) != 0u) != (wantSet != 0)) {
        if (++t >= WC_STM32_CCB_TIMEOUT) {
            return WC_TIMEOUT_E;
        }
    }
    return 0;
}

/* Common prologue shared by the three CCB ECDSA operations (blob create, blob
 * use sign, public-key scalar mult): reset/clock the CCB, select the operation
 * (CCOP) and wait for OPSTEP 0x01, condition the RNG and PKA (mode = the PKA
 * sub-operation), then wait for SAES to go idle so the blob key can be loaded.
 * The caller holds the crypto HW mutex (it owns the matching unlock). */
static int Stm32Ccb_OpBegin(word32 ccop, word32 pkaMode)
{
    int ret = Stm32Ccb_Init();
    if (ret != 0) {
        return ret;
    }
    CCB->CR = (CCB->CR & ~CCB_CR_CCOP) | ccop;
    if ((ret = Stm32Ccb_WaitOpStep(0x01u)) != 0) {
        return ret;
    }
    if ((ret = Stm32Ccb_RngInit()) != 0) {
        return ret;
    }
    if ((ret = Stm32Ccb_PkaInit(pkaMode)) != 0) {
        return ret;
    }
    return Stm32Ccb_SaesWaitSr(AES_SR_BUSY, 0);
}

/* Load the DHUK blob key into SAES (KEYSEL=HW, 256-bit, GCM) and wait for the
 * CCB to advance. isUse=1 selects decrypt (MODE_1) for blob use (sign / pubkey)
 * and the CCB reaches OPSTEP 0x12; isUse=0 selects encrypt for blob creation and
 * the CCB reaches OPSTEP 0x02. */
static int Stm32Ccb_LoadBlobKey(int isUse)
{
    word32 cr = AES_CR_KEYSEL_0 | AES_CR_KEYSIZE | STM32_AES_CHMOD_GCM;
    int    ret;

    if (isUse) {
        cr |= AES_CR_MODE_1;
    }
    SAES->CR = cr;
    if ((ret = Stm32Ccb_SaesWaitSr(AES_SR_KEYVALID, 1)) != 0) {
        return ret;
    }
    return Stm32Ccb_WaitOpStep(isUse ? 0x12u : 0x02u);
}

/* CCB RNG draw wait: spin until RNG_SR.DRDY with a bounded timeout. */
static int Stm32Ccb_RngWaitDrdy(void)
{
    word32 t = 0;
    while ((RNG->SR & RNG_SR_DRDY) == 0u) {
        if (++t >= WC_STM32_CCB_TIMEOUT) {
            return WC_TIMEOUT_E;
        }
    }
    return 0;
}

/* CCB SAES busy wait: spin until SAES_SR.BUSY clears with a bounded timeout. */
static int Stm32Ccb_SaesWaitBusy(void)
{
    word32 t = 0;
    while ((SAES->SR & AES_SR_BUSY) != 0u) {
        if (++t >= WC_STM32_CCB_TIMEOUT) {
            return WC_TIMEOUT_E;
        }
    }
    return 0;
}

/* Load the four blob IV words into SAES IVR0..IVR3 (blob-use ordering). */
static void Stm32Ccb_LoadIv(const word32* v)
{
    SAES->IVR0 = v[0];
    SAES->IVR1 = v[1];
    SAES->IVR2 = v[2];
    SAES->IVR3 = v[3];
}

/* Load the four reference-tag words into the CCB REFTAGR registers. */
static void Stm32Ccb_LoadRefTag(const word32* v)
{
    CCB->REFTAGR[0] = v[0];
    CCB->REFTAGR[1] = v[1];
    CCB->REFTAGR[2] = v[2];
    CCB->REFTAGR[3] = v[3];
}

/* Load the 32-byte hash into PKA RAM as big-endian -> little-endian words. */
static void Stm32Ccb_LoadHash(const byte* hash)
{
    word32 i;
    for (i = 0u; i < 8u; i++) {
        WC_CCB_PKA_RAMW[PKA_ECDSA_SIGN_IN_HASH_E + i] =
            (word32)hash[(32u - (i * 4u)) - 1u] |
            ((word32)hash[(32u - (i * 4u)) - 2u] << 8) |
            ((word32)hash[(32u - (i * 4u)) - 3u] << 16) |
            ((word32)hash[(32u - (i * 4u)) - 4u] << 24);
    }
}

/* Blob-use GCM final phase: feed the length block, wait CCF, and verify the
 * integrity tag reads back all-zero (nonzero => blob tag mismatch). Shared by
 * the scalar-mul (public-key) and ECDSA sign blob-use paths. */
static int Stm32Ccb_GcmFinalTagCheck(word32 opsz, word32 cipsz)
{
    word32 i;
    int ret;
    SAES->CR = (SAES->CR & ~WC_STM32_AES_CR_PHASE) | WC_STM32_AES_CR_PHASE_0 |
               WC_STM32_AES_CR_PHASE_1;
    SAES->DINR = 0u;
    SAES->DINR = WC_CCB_GCM_HDR_LEN(opsz);
    SAES->DINR = 0u;
    SAES->DINR = cipsz * 32u;
    if ((ret = Stm32Ccb_SaesWaitCcf()) != 0) {
        return ret;
    }
    for (i = 0u; i < 4u; i++) {
        if (SAES->DOUTR != 0u) {   /* nonzero => blob tag mismatch */
            return WC_HW_E;
        }
    }
    return 0;
}

/* Bare CCB public-key computation: scalar mult d*G via the blob. Mirrors the
 * blob-use sign path, but loads the unwrapped scalar into the K slot (no random
 * k) and reads the resulting point into pubX/pubY. */
static int Stm32Ccb_ComputePub(const byte* iv, const byte* tag,
    const byte* wrapped, byte* pubX, byte* pubY)
{
    word32 ivw[4];
    word32 tagw[4];
    word32 wrapw[8];
    word32 opsz;
    word32 cipsz;
    word32 off;
    word32 block;
    word32 i;
    int ret;

    XMEMCPY(ivw,   iv,      sizeof(ivw));
    XMEMCPY(tagw,  tag,     sizeof(tagw));
    XMEMCPY(wrapw, wrapped, sizeof(wrapw));
    opsz  = WC_CCB_P256_OPSZ;
    cipsz = WC_CCB_P256_CIPSZ;

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }
    ret = Stm32Ccb_OpBegin(WC_CCB_OP_SCALAR_USE, WC_CCB_PKA_MUL_MODE);
    if (ret != 0) { goto done; }
    if ((ret = Stm32Ccb_LoadBlobKey(1 /* use */)) != 0) { goto done; }

    Stm32Ccb_LoadIv(ivw);
    SAES->CR |= AES_CR_EN;
    if ((ret = Stm32Ccb_SaesWaitCcf()) != 0) { goto done; }
    Stm32Ccb_LoadRefTag(tagw);
    /* SAES GCM/chaining-phase field: STM32C5 names it AES_CR_CPHASE, U3 names it
     * AES_CR_GCMPH -- same bit positions/values. WC_STM32_AES_CR_PHASE abstracts
     * the name (port/st/stm32.h). This was the one genuinely-divergent part of
     * the OPSTEP driver; the rest is already family-neutral (WC_STM32_CCB_*). */
    SAES->CR = (SAES->CR & ~WC_STM32_AES_CR_PHASE) | WC_STM32_AES_CR_PHASE_0 |
               AES_CR_EN;
    if ((ret = Stm32Ccb_WaitOpStep(0x13u)) != 0) { goto done; }

    if ((ret = Stm32Ccb_LoadCurve()) != 0) { goto done; }
    SAES->CR = (SAES->CR & ~WC_STM32_AES_CR_PHASE) | WC_STM32_AES_CR_PHASE_1;
    if ((ret = Stm32Ccb_WaitOpStep(0x14u)) != 0) { goto done; }

    block = 0u;
    for (off = 0u; off < cipsz; off++) {
        SAES->DINR = wrapw[cipsz - 1u - off];
        if ((off % 4u) == 3u) {
            if ((ret = Stm32Ccb_SaesWaitCcf()) != 0) { goto done; }
            for (i = 0u; i < 4u; i++) {
                WC_CCB_PKA_RAMW[PKA_ECC_SCALAR_MUL_IN_K + block + i] = WC_CCB_MAGIC;
            }
            block += 4u;
        }
    }
    WC_CCB_PKA_RAMW[PKA_ECC_SCALAR_MUL_IN_K + cipsz]      = 0u;
    WC_CCB_PKA_RAMW[PKA_ECC_SCALAR_MUL_IN_K + cipsz + 1u] = 0u;
    if ((ret = Stm32Ccb_WaitOpStep(0x17u)) != 0) { goto done; }

    if ((ret = Stm32Ccb_GcmFinalTagCheck(opsz, cipsz)) != 0) { goto done; }
    if ((ret = Stm32Ccb_WaitOpStep(0x18u)) != 0) { goto done; }

    PKA->CR |= PKA_CR_START;
    if ((ret = Stm32Ccb_WaitOpStep(0x19u)) != 0) { goto done; }
    if ((ret = Stm32Ccb_PkaWaitFlag(PKA_SR_PROCENDF)) != 0) { goto done; }
    if ((ret = Stm32Ccb_WaitOpStep(0x1Au)) != 0) { goto done; }

    wc_stm32_pka_read_be(pubX, &WC_CCB_PKA_RAMW[PKA_ECC_SCALAR_MUL_OUT_RESULT_X], 32u);
    wc_stm32_pka_read_be(pubY, &WC_CCB_PKA_RAMW[PKA_ECC_SCALAR_MUL_OUT_RESULT_Y], 32u);
    ret = 0;

done:
    Stm32Ccb_Reset();
    SAES->CR &= ~AES_CR_EN;
    wolfSSL_CryptHwMutexUnLock();
    return ret;
}

/* Bare CCB ECDSA blob creation (P-256, CPU-supplied scalar). Produces the
 * device-bound blob {iv, tag, wrapped d}; the clear scalar is fed to the SAES,
 * encrypted under the DHUK, and read back encrypted -- it never persists in
 * software here beyond the caller's input. The public key is derived by a
 * separate compute step (left to the caller / wc_ecc layer). */
int wc_Stm32_Ccb_EccMakeBlob(int curveId, const byte* d, word32 dLen,
    byte* iv, byte* tag, byte* wrapped, word32* wrappedSz,
    byte* pubX, byte* pubY)
{
    word32 ivw[4];
    word32 tagw[4];
    word32 wrapw[8];
    word32 opsz;
    word32 cipsz;
    word32 off;
    word32 block;
    word32 i;
    int ret;

    if (curveId != ECC_SECP256R1) {
        return NOT_COMPILED_IN;
    }
    /* Require pubX/pubY non-NULL to match the CubeMX/HAL implementation's
     * contract (one public API, one NULL-handling rule across build flavors). */
    if (d == NULL || dLen != 32u || iv == NULL || tag == NULL ||
        wrapped == NULL || wrappedSz == NULL || pubX == NULL || pubY == NULL) {
        return BAD_FUNC_ARG;
    }
    opsz  = WC_CCB_P256_OPSZ;
    cipsz = WC_CCB_P256_CIPSZ;

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }
    /* CCOP = ECDSA CPU blob creation; load the DHUK blob key in encrypt mode. */
    ret = Stm32Ccb_OpBegin(WC_CCB_OP_CREATE, WC_CCB_PKA_SIGN_MODE);
    if (ret != 0) { goto done; }
    if ((ret = Stm32Ccb_LoadBlobKey(0 /* create */)) != 0) { goto done; }

    /* Blob-creation initial phase: IVR0=2, IVR1-3 randomised by CCB, read the
     * generated IV back, GCM init, header phase. */
    SAES->IVR0 = 0x00000002u;
    if ((ret = Stm32Ccb_RngWaitDrdy()) != 0) { goto done; }
    SAES->IVR1 = WC_CCB_FAKE;
    if ((ret = Stm32Ccb_RngWaitDrdy()) != 0) { goto done; }
    SAES->IVR2 = WC_CCB_FAKE;
    if ((ret = Stm32Ccb_RngWaitDrdy()) != 0) { goto done; }
    SAES->IVR3 = WC_CCB_FAKE;
    if ((ret = Stm32Ccb_RngWaitDrdy()) != 0) { goto done; }
    if ((PKA->SR & PKA_SR_RNGERRF) != 0u) { ret = WC_HW_E; goto done; }
    ivw[3] = SAES->IVR3;
    ivw[2] = SAES->IVR2;
    ivw[1] = SAES->IVR1;
    ivw[0] = SAES->IVR0;
    SAES->CR |= AES_CR_EN;
    if ((ret = Stm32Ccb_SaesWaitCcf()) != 0) { goto done; }
    SAES->CR = (SAES->CR & ~WC_STM32_AES_CR_PHASE) | WC_STM32_AES_CR_PHASE_0 | AES_CR_EN;
    if ((ret = Stm32Ccb_WaitOpStep(0x03u)) != 0) { goto done; }

    /* Curve params (coupled), then GCM payload phase. */
    if ((ret = Stm32Ccb_LoadCurve()) != 0) { goto done; }
    SAES->CR = (SAES->CR & ~WC_STM32_AES_CR_PHASE) | WC_STM32_AES_CR_PHASE_1;
    if ((ret = Stm32Ccb_WaitOpStep(0x04u)) != 0) { goto done; }

    /* CPU writes the clear scalar d into PKA RAM (BE->LE words from the end). */
    PKA->CLRFR = PKA_CLRFR_CMFC;
    for (off = 0u; off < (opsz - 2u); off += 2u) {
        Stm32Ccb_Wr64(PKA_ECDSA_SIGN_IN_PRIVATE_KEY_D + off,
                      &d[32u - ((off * 4u) + 1u)]);
    }
    WC_CCB_PKA_RAMW[PKA_ECDSA_SIGN_IN_PRIVATE_KEY_D + off]      = 0u;
    WC_CCB_PKA_RAMW[PKA_ECDSA_SIGN_IN_PRIVATE_KEY_D + off + 1u] = 0u;
    if ((ret = Stm32Ccb_PkaWaitFlag(PKA_SR_DATAOKF)) != 0) { goto done; }
    if ((ret = Stm32Ccb_WaitOpStep(0x08u)) != 0) { goto done; }

    /* Read back the encrypted scalar from the SAES: writing the magic value to
     * PKA RAM triggers the chaining, every 4th word yields a 128-bit block. */
    PKA->CLRFR = PKA_CLRFR_CMFC;
    block = 0u;
    for (off = 0u; off < cipsz; off++) {
        WC_CCB_PKA_RAMW[PKA_ECDSA_SIGN_IN_PRIVATE_KEY_D + off] = WC_CCB_MAGIC;
        if ((off % 4u) == 3u) {
            if ((ret = Stm32Ccb_SaesWaitCcf()) != 0) { goto done; }
            for (i = 0u; i < 4u; i++) {
                wrapw[cipsz - (block + i + 1u)] = SAES->DOUTR;
            }
            block += 4u;
        }
    }
    if ((ret = Stm32Ccb_SaesWaitBusy()) != 0) { goto done; }
    WC_CCB_PKA_RAMW[PKA_ECDSA_SIGN_IN_PRIVATE_KEY_D + cipsz]      = 0u;
    WC_CCB_PKA_RAMW[PKA_ECDSA_SIGN_IN_PRIVATE_KEY_D + cipsz + 1u] = 0u;
    if ((ret = Stm32Ccb_PkaWaitFlag(PKA_SR_DATAOKF)) != 0) { goto done; }

#if defined(WOLFSSL_STM32C5)
    /* STM32C5: blob-create is a combined create+SIGN -- the OPSTEP machine only
     * advances through the GCM-final tag phase if the random k is drawn and the
     * PKA sign is started. Draw k, run the GCM final phase, read the tag, then
     * START the PKA; the resulting r,s are a creation by-product and discarded
     * (the blob is still {iv, tag, wrapped}). Mirrors the C5 HAL
     * CCB_ECDSA_SignBlobCreation. The U3 OPSTEP machine does not require this. */
    if ((ret = Stm32Ccb_WaitOpStep(0x09u)) != 0) { goto done; }
    for (off = 0u; off < (opsz - 2u); off++) {
        if ((ret = Stm32Ccb_RngWaitDrdy()) != 0) { goto done; }
        WC_CCB_PKA_RAMW[PKA_ECDSA_SIGN_IN_K + off] = WC_CCB_MAGIC;
    }
    if ((PKA->SR & PKA_SR_RNGERRF) != 0u) { ret = WC_HW_E; goto done; }
    WC_CCB_PKA_RAMW[PKA_ECDSA_SIGN_IN_K + (opsz - 2u)]      = 0u;
    WC_CCB_PKA_RAMW[PKA_ECDSA_SIGN_IN_K + (opsz - 2u) + 1u] = 0u;
    if ((ret = Stm32Ccb_PkaWaitFlag(PKA_SR_RNGOKF)) != 0) { goto done; }
    if ((ret = Stm32Ccb_SaesWaitBusy()) != 0) { goto done; }
    SAES->CR = (SAES->CR & ~WC_STM32_AES_CR_PHASE) | WC_STM32_AES_CR_PHASE_0 | WC_STM32_AES_CR_PHASE_1;
    PKA->CLRFR = PKA_CLRFR_CMFC;
    SAES->DINR = 0u;
    SAES->DINR = WC_CCB_GCM_HDR_LEN(opsz);
    SAES->DINR = 0u;
    SAES->DINR = cipsz * 32u;
    if ((ret = Stm32Ccb_SaesWaitCcf()) != 0) { goto done; }
    for (i = 0u; i < 4u; i++) {
        tagw[i] = SAES->DOUTR;
    }
    PKA->CR |= PKA_CR_START;
    if ((ret = Stm32Ccb_PkaWaitFlag(PKA_SR_PROCENDF)) != 0) { goto done; }
    if ((ret = Stm32Ccb_WaitOpStep(0x1Au)) != 0) { goto done; }
    if (WC_CCB_PKA_RAMW[PKA_ECDSA_SIGN_OUT_ERROR] != WC_CCB_PKA_OK) {
        ret = WC_HW_E;
        goto done;
    }
#else
    /* GCM final phase: feed the length block and read the authentication tag. */
    SAES->CR = (SAES->CR & ~WC_STM32_AES_CR_PHASE) | WC_STM32_AES_CR_PHASE_0 | WC_STM32_AES_CR_PHASE_1;
    if ((ret = Stm32Ccb_WaitOpStep(0x0Au)) != 0) { goto done; }
    PKA->CLRFR = PKA_CLRFR_CMFC;
    SAES->DINR = 0u;
    SAES->DINR = WC_CCB_GCM_HDR_LEN(opsz);
    SAES->DINR = 0u;
    SAES->DINR = cipsz * 32u;
    if ((ret = Stm32Ccb_SaesWaitCcf()) != 0) { goto done; }
    for (i = 0u; i < 4u; i++) {
        tagw[i] = SAES->DOUTR;
    }
#endif

    XMEMCPY(iv,      ivw,   sizeof(ivw));
    XMEMCPY(tag,     tagw,  sizeof(tagw));
    XMEMCPY(wrapped, wrapw, sizeof(wrapw));
    *wrappedSz = (word32)sizeof(wrapw);
    ret = 0;

done:
    Stm32Ccb_Reset();
    SAES->CR &= ~AES_CR_EN;
    wolfSSL_CryptHwMutexUnLock();
    /* Derive the public key from the fresh blob (separate locked op).
     * pubX/pubY are guaranteed non-NULL by the argument check above. */
    if (ret == 0) {
        ret = Stm32Ccb_ComputePub(iv, tag, wrapped, pubX, pubY);
    }
    return ret;
}

/* Bare CCB ECDSA blob-use sign (P-256). Drives the CCB OPSTEP machine
 * 0x01 -> 0x12 -> 0x13 -> 0x14 -> 0x16 -> 0x17 -> 0x18 -> 0x19 -> 0x1A. */
int wc_Stm32_Ccb_EccSign(int curveId, const byte* iv, const byte* tag,
    const byte* wrapped, word32 wrappedSz, const byte* hash, word32 hashSz,
    byte* r, byte* s)
{
    word32 ivw[4];
    word32 tagw[4];
    word32 wrapw[8];
    word32 opsz;
    word32 cipsz;
    word32 off;
    word32 block;
    word32 i;
    int ret;

    if (curveId != ECC_SECP256R1) {
        return NOT_COMPILED_IN;
    }
    if (iv == NULL || tag == NULL || wrapped == NULL || wrappedSz != 32u ||
        hash == NULL || hashSz < 32u || r == NULL || s == NULL) {
        return BAD_FUNC_ARG;
    }
    XMEMCPY(ivw,   iv,      sizeof(ivw));
    XMEMCPY(tagw,  tag,     sizeof(tagw));
    XMEMCPY(wrapw, wrapped, sizeof(wrapw));

    opsz  = WC_CCB_P256_OPSZ;
    cipsz = WC_CCB_P256_CIPSZ;

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }
    /* CCOP = ECDSA blob-use sign; load the DHUK blob key in decrypt (use) mode. */
    ret = Stm32Ccb_OpBegin(WC_CCB_OP_SIGN_USE, WC_CCB_PKA_SIGN_MODE);
    if (ret != 0) { goto done; }
    if ((ret = Stm32Ccb_LoadBlobKey(1 /* use */)) != 0) { goto done; }

    /* Hash -> PKA RAM (plain BE->LE words, no terminator, not yet coupled). */
    Stm32Ccb_LoadHash(hash);

    /* Blob-use initial phase: load IV, GCM init, write reference tag. */
    Stm32Ccb_LoadIv(ivw);
    SAES->CR |= AES_CR_EN;
    if ((ret = Stm32Ccb_SaesWaitCcf()) != 0) { goto done; }
    Stm32Ccb_LoadRefTag(tagw);
    /* GCM header phase (keep EN) -> OPSTEP 0x12 -> 0x13. */
    SAES->CR = (SAES->CR & ~WC_STM32_AES_CR_PHASE) | WC_STM32_AES_CR_PHASE_0 | AES_CR_EN;
    if ((ret = Stm32Ccb_WaitOpStep(0x13u)) != 0) { goto done; }

    /* ECDSA curve params into PKA RAM (each coupled to SAES, wait CCF). */
    if ((ret = Stm32Ccb_LoadCurve()) != 0) { goto done; }

    /* GCM payload phase -> OPSTEP 0x13 -> 0x14. */
    SAES->CR = (SAES->CR & ~WC_STM32_AES_CR_PHASE) | WC_STM32_AES_CR_PHASE_1;
    if ((ret = Stm32Ccb_WaitOpStep(0x14u)) != 0) { goto done; }

    /* Feed the wrapped scalar to SAES; the CCB substitutes the decrypted key
     * into PKA RAM where the magic value is written (SAES->PKA chaining). */
    block = 0u;
    for (off = 0u; off < cipsz; off++) {
        SAES->DINR = wrapw[cipsz - 1u - off];
        if ((off % 4u) == 3u) {
            if ((ret = Stm32Ccb_SaesWaitCcf()) != 0) { goto done; }
            for (i = 0u; i < 4u; i++) {
                WC_CCB_PKA_RAMW[PKA_ECDSA_SIGN_IN_PRIVATE_KEY_D + block + i] =
                    WC_CCB_MAGIC;
            }
            block += 4u;
        }
    }
    WC_CCB_PKA_RAMW[PKA_ECDSA_SIGN_IN_PRIVATE_KEY_D + cipsz]      = 0u;
    WC_CCB_PKA_RAMW[PKA_ECDSA_SIGN_IN_PRIVATE_KEY_D + cipsz + 1u] = 0u;
    if ((ret = Stm32Ccb_PkaWaitFlag(PKA_SR_DATAOKF)) != 0) { goto done; }
    if ((ret = Stm32Ccb_WaitOpStep(0x16u)) != 0) { goto done; }

    /* Per-nonce k drawn by the RNG over CCB (CPU writes placeholders). */
    for (off = 0u; off < (opsz - 2u); off++) {
        if ((ret = Stm32Ccb_RngWaitDrdy()) != 0) { goto done; }
        WC_CCB_PKA_RAMW[PKA_ECDSA_SIGN_IN_K + off] = WC_CCB_FAKE;
    }
    WC_CCB_PKA_RAMW[PKA_ECDSA_SIGN_IN_K + (opsz - 2u)]      = 0u;
    WC_CCB_PKA_RAMW[PKA_ECDSA_SIGN_IN_K + (opsz - 2u) + 1u] = 0u;
    if ((ret = Stm32Ccb_PkaWaitFlag(PKA_SR_RNGOKF)) != 0) { goto done; }
    if ((ret = Stm32Ccb_WaitOpStep(0x17u)) != 0) { goto done; }

    /* Blob-use final phase: GCM length block + tag-integrity check. */
    if ((ret = Stm32Ccb_GcmFinalTagCheck(opsz, cipsz)) != 0) { goto done; }
    if ((ret = Stm32Ccb_WaitOpStep(0x18u)) != 0) { goto done; }

    /* Run the PKA ECDSA signature. */
    PKA->CR |= PKA_CR_START;
    if ((ret = Stm32Ccb_WaitOpStep(0x19u)) != 0) { goto done; }
    if ((ret = Stm32Ccb_PkaWaitFlag(PKA_SR_PROCENDF)) != 0) { goto done; }
    if ((ret = Stm32Ccb_WaitOpStep(0x1Au)) != 0) { goto done; }

    if (WC_CCB_PKA_RAMW[PKA_ECDSA_SIGN_OUT_ERROR] != WC_CCB_PKA_OK) {
        ret = WC_HW_E;
        goto done;
    }
    wc_stm32_pka_read_be(r, &WC_CCB_PKA_RAMW[PKA_ECDSA_SIGN_OUT_SIGNATURE_R], 32u);
    wc_stm32_pka_read_be(s, &WC_CCB_PKA_RAMW[PKA_ECDSA_SIGN_OUT_SIGNATURE_S], 32u);
    ret = 0;

done:
    Stm32Ccb_Reset();
    SAES->CR &= ~AES_CR_EN;
    wolfSSL_CryptHwMutexUnLock();
    return ret;
}
#endif /* WOLFSSL_STM32_CCB */

#endif /* WC_STM32_HAS_DHUK */
#endif /* WOLFSSL_DHUK */


#elif defined(WOLFSSL_STM32_CUBEMX)

#if defined(WOLFSSL_DHUK)
/* Wrap an AES key using the DHUK */
int wc_Stm32_Aes_Wrap(struct Aes* aes, const byte* in, word32 inSz, byte* out,
    word32* outSz, const byte* iv, int ivSz)
{
    CRYP_HandleTypeDef hcryp;
    int ret = 0;
    byte key[AES_256_KEY_SIZE];

    /* SAES requires use of the RNG -- HAL_RNG_DeInit() calls from random.c
        turn off the RNG clock -- re-enable the clock here */
    __HAL_RCC_RNG_CLK_ENABLE();
    ByteReverseWords((word32*)key, (word32*)in, inSz);
    XMEMSET(&hcryp, 0, sizeof(CRYP_HandleTypeDef));
    if (ret == 0) {
        hcryp.Instance       = SAES;
        hcryp.Init.DataType  = CRYP_DATATYPE_8B;
        hcryp.Init.KeySize   = CRYP_KEYSIZE_256B;
        hcryp.Init.DataWidthUnit = CRYP_DATAWIDTHUNIT_BYTE;
        hcryp.Init.KeySelect = CRYP_KEYSEL_HW; /* use DHUK to unwrap with use */
        hcryp.Init.KeyMode   = CRYP_KEYMODE_WRAPPED;
        if (iv != NULL) {
            hcryp.Init.pInitVect = (uint32_t *)iv;
            hcryp.Init.Algorithm = CRYP_AES_CBC;
        }
        else {
            hcryp.Init.Algorithm = CRYP_AES_ECB;
        }
        ret = HAL_CRYP_Init(&hcryp);
    }

    if (ret == HAL_OK) {
        ret = HAL_CRYPEx_WrapKey(&hcryp, (uint32_t*)key, (uint32_t*)out, 100);
        HAL_CRYP_DeInit(&hcryp);
    }
    ForceZero(key, sizeof(key));

    ByteReverseWords((word32*)out, (word32*)out, inSz);
    *outSz = inSz;
    (void)aes;
    return ret;
}


#endif

int wc_Stm32_Aes_Init(Aes* aes, CRYP_HandleTypeDef* hcryp, int useSaes)
{
    int ret;
    word32 keySize;
#ifdef STM32_HW_CLOCK_AUTO
    /* enable the peripheral clock */
    __HAL_RCC_CRYP_CLK_ENABLE();
#endif

    ret = wc_AesGetKeySize(aes, &keySize);
    if (ret != 0)
        return ret;

    XMEMSET(hcryp, 0, sizeof(CRYP_HandleTypeDef));
    switch (keySize) {
        case 16: /* 128-bit key */
            hcryp->Init.KeySize = CRYP_KEYSIZE_128B;
            break;
    #ifdef CRYP_KEYSIZE_192B
        case 24: /* 192-bit key */
            hcryp->Init.KeySize = CRYP_KEYSIZE_192B;
            break;
    #endif
        case 32: /* 256-bit key */
            hcryp->Init.KeySize = CRYP_KEYSIZE_256B;
            break;
        default:
            break;
    }

#ifdef WOLFSSL_DHUK
    /* Use hardware key */
    if (useSaes && (aes->devId == WOLFSSL_DHUK_DEVID ||
            aes->devId == WOLFSSL_SAES_DEVID)) {

            /* SAES requires use of the RNG -- HAL_RNG_DeInit() calls from
               random.c turn off the RNG clock -- re-enable the clock here */
            __HAL_RCC_RNG_CLK_ENABLE();

            hcryp->Instance       = SAES;
            hcryp->Init.DataType  = CRYP_DATATYPE_8B;

            /* Key select (HW, or Normal) */
            if (aes->devId == WOLFSSL_DHUK_DEVID) {
                hcryp->Init.KeySelect = CRYP_KEYSEL_HW;
            }
            else {
                hcryp->Init.KeySelect = CRYP_KEYSEL_NORMAL;
                hcryp->Init.KeyMode   = CRYP_KEYMODE_NORMAL;
                hcryp->Init.pKey      = (uint32_t*)aes->key;
            }
    } else
#endif
    {
        hcryp->Instance = CRYP;
        hcryp->Init.DataType = CRYP_DATATYPE_8B;
        hcryp->Init.pKey = (STM_CRYPT_TYPE*)aes->key;
    }
#ifdef STM32_HAL_V2
    hcryp->Init.DataWidthUnit = CRYP_DATAWIDTHUNIT_BYTE;
    #if defined(CRYP_HEADERWIDTHUNIT_BYTE) && defined(STM_CRYPT_HEADER_WIDTH)
    hcryp->Init.HeaderWidthUnit =
            (STM_CRYPT_HEADER_WIDTH == 4) ?
                CRYP_HEADERWIDTHUNIT_WORD :
                CRYP_HEADERWIDTHUNIT_BYTE;
    #endif
#endif

    return 0;
}

void wc_Stm32_Aes_Cleanup(void)
{
#ifdef STM32_HW_CLOCK_AUTO
    /* disable the peripheral clock */
    __HAL_RCC_CRYP_CLK_DISABLE();
#endif
}
#else /* Standard Peripheral Library */

int wc_Stm32_Aes_Init(Aes* aes, CRYP_InitTypeDef* cryptInit,
    CRYP_KeyInitTypeDef* keyInit)
{
    int ret;
    word32 keySize;
    word32* aes_key;

    ret = wc_AesGetKeySize(aes, &keySize);
    if (ret != 0)
        return ret;

    aes_key = aes->key;

    /* crypto structure initialization */
    CRYP_KeyStructInit(keyInit);
    CRYP_StructInit(cryptInit);

    /* load key into correct registers */
    switch (keySize) {
        case 16: /* 128-bit key */
            cryptInit->CRYP_KeySize = CRYP_KeySize_128b;
            keyInit->CRYP_Key2Left  = aes_key[0];
            keyInit->CRYP_Key2Right = aes_key[1];
            keyInit->CRYP_Key3Left  = aes_key[2];
            keyInit->CRYP_Key3Right = aes_key[3];
            break;

        case 24: /* 192-bit key */
            cryptInit->CRYP_KeySize = CRYP_KeySize_192b;
            keyInit->CRYP_Key1Left  = aes_key[0];
            keyInit->CRYP_Key1Right = aes_key[1];
            keyInit->CRYP_Key2Left  = aes_key[2];
            keyInit->CRYP_Key2Right = aes_key[3];
            keyInit->CRYP_Key3Left  = aes_key[4];
            keyInit->CRYP_Key3Right = aes_key[5];
            break;

        case 32: /* 256-bit key */
            cryptInit->CRYP_KeySize = CRYP_KeySize_256b;
            keyInit->CRYP_Key0Left  = aes_key[0];
            keyInit->CRYP_Key0Right = aes_key[1];
            keyInit->CRYP_Key1Left  = aes_key[2];
            keyInit->CRYP_Key1Right = aes_key[3];
            keyInit->CRYP_Key2Left  = aes_key[4];
            keyInit->CRYP_Key2Right = aes_key[5];
            keyInit->CRYP_Key3Left  = aes_key[6];
            keyInit->CRYP_Key3Right = aes_key[7];
            break;

        default:
            break;
    }
    cryptInit->CRYP_DataType = CRYP_DataType_8b;

    return 0;
}

void wc_Stm32_Aes_Cleanup(void)
{
}

#endif /* WOLFSSL_STM32_BARE / WOLFSSL_STM32_CUBEMX / StdPeriph */

/* CubeMX/HAL CCB ECDSA port -- placed after the build-branch structure and
 * guarded on WOLFSSL_STM32_CUBEMX so it compiles only for the HAL build (the
 * BARE build provides its own wc_Stm32_Ccb_* above). */
#if defined(WOLFSSL_STM32_CCB) && defined(WOLFSSL_STM32_CUBEMX)
/* ---------------------------------------------------------------------------
 * CCB (Coupling and Chaining Bridge) ECDSA -- CubeMX/HAL path (STM32U3).
 * Implements the wolfSSL CCB port via ST's HAL_CCB_* driver. The DHUK is the
 * blob encryption key (HAL_CCB_USER_KEY_HW), so the P-256 private scalar never
 * enters software. The bare-metal counterpart lives in the BARE branch above.
 * ------------------------------------------------------------------------- */

/* NIST P-256 parameters (big-endian, 32 bytes). */
static const byte ccb_p256_aAbs[32] = {
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x03};
static const byte ccb_p256_b[32] = {
    0x5a,0xc6,0x35,0xd8,0xaa,0x3a,0x93,0xe7,0xb3,0xeb,0xbd,0x55,0x76,0x98,0x86,0xbc,
    0x65,0x1d,0x06,0xb0,0xcc,0x53,0xb0,0xf6,0x3b,0xce,0x3c,0x3e,0x27,0xd2,0x60,0x4b};
static const byte ccb_p256_p[32] = {
    0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
static const byte ccb_p256_n[32] = {
    0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xbc,0xe6,0xfa,0xad,0xa7,0x17,0x9e,0x84,0xf3,0xb9,0xca,0xc2,0xfc,0x63,0x25,0x51};
static const byte ccb_p256_Gx[32] = {
    0x6b,0x17,0xd1,0xf2,0xe1,0x2c,0x42,0x47,0xf8,0xbc,0xe6,0xe5,0x63,0xa4,0x40,0xf2,
    0x77,0x03,0x7d,0x81,0x2d,0xeb,0x33,0xa0,0xf4,0xa1,0x39,0x45,0xd8,0x98,0xc2,0x96};
static const byte ccb_p256_Gy[32] = {
    0x4f,0xe3,0x42,0xe2,0xfe,0x1a,0x7f,0x9b,0x8e,0xe7,0xeb,0x4a,0x7c,0x0f,0x9e,0x16,
    0x2b,0xce,0x33,0x57,0x6b,0x31,0x5e,0xce,0xcb,0xb6,0x40,0x68,0x37,0xbf,0x51,0xf5};

static void Stm32Ccb_SetP256(CCB_ECDSACurveParamTypeDef* p)
{
    p->primeOrderSizeByte = 32;
    p->modulusSizeByte    = 32;
    p->coefSignA          = 0x00000001u;
    p->pAbsCoefA          = ccb_p256_aAbs;
    p->pCoefB             = ccb_p256_b;
    p->pModulus           = ccb_p256_p;
    p->pPrimeOrder        = ccb_p256_n;
    p->pPointX            = ccb_p256_Gx;
    p->pPointY            = ccb_p256_Gy;
}

/* Enable the clocks for every peer the CCB chains. HAL_CCB_Init calls the weak
 * HAL_CCB_MspInit (empty unless the app provides one), so the port enables them
 * itself -- and random.c's HAL_RNG_DeInit may have gated the RNG clock off. */
static void Stm32Ccb_HalClkEnable(void)
{
    __HAL_RCC_CCB_CLK_ENABLE();
    __HAL_RCC_PKA_CLK_ENABLE();
    __HAL_RCC_SAES_CLK_ENABLE();
    __HAL_RCC_RNG_CLK_ENABLE();
}

int wc_Stm32_Ccb_EccMakeBlob(int curveId, const byte* d, word32 dLen,
    byte* iv, byte* tag, byte* wrapped, word32* wrappedSz,
    byte* pubX, byte* pubY)
{
    CCB_HandleTypeDef          hccb;
    CCB_ECDSACurveParamTypeDef param;
    CCB_WrappingKeyTypeDef     wrap;
    CCB_ECDSAKeyBlobTypeDef    blob;
    CCB_ECCMulPointTypeDef     pub;
    uint32_t ivW[4];
    uint32_t tagW[4];
    uint32_t wrapW[8];
    int ret = 0;

    if (curveId != ECC_SECP256R1) {
        return NOT_COMPILED_IN;
    }
    if (d == NULL || dLen != 32u || iv == NULL || tag == NULL ||
        wrapped == NULL || wrappedSz == NULL || pubX == NULL || pubY == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }
    Stm32Ccb_HalClkEnable();
    XMEMSET(&hccb, 0, sizeof(hccb));
    hccb.Instance = CCB;
    if (HAL_CCB_Init(&hccb) != HAL_OK) {
        wolfSSL_CryptHwMutexUnLock();
        return WC_HW_E;
    }
    Stm32Ccb_SetP256(&param);
    XMEMSET(&wrap, 0, sizeof(wrap));
    wrap.WrappingKeyType = HAL_CCB_USER_KEY_HW;
    blob.pIV = ivW;
    blob.pTag = tagW;
    blob.pWrappedKey = wrapW;

    if (HAL_CCB_ECDSA_WrapPrivateKey(&hccb, &param, d, &wrap, &blob) != HAL_OK
            || hccb.State != HAL_CCB_STATE_READY) {
        ret = WC_HW_E;
        goto out;
    }
    pub.pPointX = pubX;
    pub.pPointY = pubY;
    if (HAL_CCB_ECDSA_ComputePublicKey(&hccb, &param, &wrap, &blob, &pub)
            != HAL_OK) {
        ret = WC_HW_E;
        goto out;
    }
    XMEMCPY(iv,      ivW,   sizeof(ivW));
    XMEMCPY(tag,     tagW,  sizeof(tagW));
    XMEMCPY(wrapped, wrapW, sizeof(wrapW));
    *wrappedSz = (word32)sizeof(wrapW);

out:
    (void)HAL_CCB_DeInit(&hccb);
    wolfSSL_CryptHwMutexUnLock();
    return ret;
}

int wc_Stm32_Ccb_EccSign(int curveId, const byte* iv, const byte* tag,
    const byte* wrapped, word32 wrappedSz, const byte* hash, word32 hashSz,
    byte* r, byte* s)
{
    CCB_HandleTypeDef          hccb;
    CCB_ECDSACurveParamTypeDef param;
    CCB_WrappingKeyTypeDef     wrap;
    CCB_ECDSAKeyBlobTypeDef    blob;
    CCB_ECDSASignTypeDef       sig;
    uint32_t ivW[4];
    uint32_t tagW[4];
    uint32_t wrapW[8];
    int ret = 0;

    if (curveId != ECC_SECP256R1) {
        return NOT_COMPILED_IN;
    }
    if (iv == NULL || tag == NULL || wrapped == NULL || wrappedSz != 32u ||
        hash == NULL || hashSz < 32u || r == NULL || s == NULL) {
        return BAD_FUNC_ARG;
    }
    XMEMCPY(ivW,   iv,      sizeof(ivW));
    XMEMCPY(tagW,  tag,     sizeof(tagW));
    XMEMCPY(wrapW, wrapped, sizeof(wrapW));

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }
    Stm32Ccb_HalClkEnable();
    XMEMSET(&hccb, 0, sizeof(hccb));
    hccb.Instance = CCB;
    if (HAL_CCB_Init(&hccb) != HAL_OK) {
        wolfSSL_CryptHwMutexUnLock();
        return WC_HW_E;
    }
    Stm32Ccb_SetP256(&param);
    XMEMSET(&wrap, 0, sizeof(wrap));
    wrap.WrappingKeyType = HAL_CCB_USER_KEY_HW;
    blob.pIV = ivW;
    blob.pTag = tagW;
    blob.pWrappedKey = wrapW;
    sig.pRSign = r;
    sig.pSSign = s;
    if (HAL_CCB_ECDSA_Sign(&hccb, &param, &wrap, &blob, (uint8_t*)hash, &sig)
            != HAL_OK) {
        ret = WC_HW_E;
    }
    (void)HAL_CCB_DeInit(&hccb);
    wolfSSL_CryptHwMutexUnLock();
    return ret;
}

#if defined(WOLF_CRYPTO_CB) && defined(HAVE_ECC) && defined(HAVE_ECC_SIGN)
/* CubeMX CCB crypto-callback device. Transparent DHUK AES/GMAC is bare-only, so
 * under the HAL build the CCB-protected ECDSA sign is the only transparent DHUK
 * operation. This minimal device routes WC_PK_TYPE_ECDSA_SIGN for a CCB key
 * (key->dhuk_is_ccb) to the HAL CCB sign and returns the DER-encoded (r,s); it
 * mirrors the bare-metal device's CCB branch so the same wc_ecc_sign_hash flow
 * works on both build paths. */
static int Stm32Ccb_CryptoDevCb(int devId, struct wc_CryptoInfo* info,
                                void* ctx)
{
    ecc_key* key;
    byte     r[MAX_ECC_BYTES];
    byte     s[MAX_ECC_BYTES];
    word32   sz;
    int      ret;

    (void)devId;
    (void)ctx;
    if (info == NULL || info->algo_type != WC_ALGO_TYPE_PK) {
        return CRYPTOCB_UNAVAILABLE;
    }
    /* Transparent provisioning: wc_ecc_make_key() on a WC_DHUK_DEVID key binds
     * a fresh CCB-protected blob to it (no CCB-specific API). */
    if (info->pk.type == WC_PK_TYPE_EC_KEYGEN) {
        return wc_ecc_dev_make_key(info->pk.eckg.rng, info->pk.eckg.size,
            info->pk.eckg.key, info->pk.eckg.curveId);
    }
    if (info->pk.type != WC_PK_TYPE_ECDSA_SIGN) {
        return CRYPTOCB_UNAVAILABLE;
    }
    key = info->pk.eccsign.key;
    if (key == NULL || key->dhuk_is_ccb == 0u) {
        return CRYPTOCB_UNAVAILABLE;
    }
    sz = (word32)wc_ecc_size(key);
    ret = wc_Stm32_Ccb_EccSign(ECC_SECP256R1, key->ccb_iv, key->ccb_tag,
                               key->dhuk_wrapped_priv,
                               key->dhuk_wrapped_priv_len,
                               info->pk.eccsign.in, info->pk.eccsign.inlen,
                               r, s);
    if (ret == 0) {
        ret = wc_ecc_rs_raw_to_sig(r, sz, s, sz,
                                   info->pk.eccsign.out,
                                   info->pk.eccsign.outlen);
    }
    ForceZero(r, sizeof(r));
    ForceZero(s, sizeof(s));
    return ret;
}

/* Register / unregister the STM32 DHUK/CCB device for the CubeMX build. Same
 * name and contract as the bare-metal version so callers are build-agnostic. */
int wc_Stm32_DhukRegister(int devId)
{
    return wc_CryptoCb_RegisterDevice(devId, Stm32Ccb_CryptoDevCb, NULL);
}

void wc_Stm32_DhukUnRegister(int devId)
{
    wc_CryptoCb_UnRegisterDevice(devId);
}
#endif /* WOLF_CRYPTO_CB && HAVE_ECC && HAVE_ECC_SIGN */
#endif /* WOLFSSL_STM32_CCB && WOLFSSL_STM32_CUBEMX */
#endif /* !NO_AES */
#endif /* STM32_CRYPTO */

#ifdef WOLFSSL_STM32_PKA

/* Reverse array in memory (in place) */
#ifdef HAVE_ECC

/* convert from mp_int to STM32 PKA HAL integer, as array of bytes of size sz.
 * if mp_int has less bytes than sz, add zero bytes at most significant byte
 * positions.
 * This is when for example modulus is 32 bytes (P-256 curve)
 * and mp_int has only 31 bytes, we add leading zeros
 * so that result array has 32 bytes, same as modulus (sz).
 */
static int stm32_get_from_mp_int(uint8_t *dst, const mp_int *a, int sz)
{
    int res, szbin, offset;

    if (dst == NULL || a == NULL || sz < 0)
        return BAD_FUNC_ARG;

    /* check how many bytes are in the mp_int */
    szbin = mp_unsigned_bin_size(a);
    if (szbin < 0 || szbin > sz)
        return BUFFER_E;

    /* compute offset from dst */
    offset = sz - szbin;
    if (offset < 0)
        offset = 0;
    if (offset > sz)
        offset = sz;

    /* add leading zeroes */
    if (offset)
        XMEMSET(dst, 0, offset);

    /* convert mp_int to array of bytes */
    res = mp_to_unsigned_bin(a, dst + offset);
    return res;
}

static int stm32_getabs_from_mp_int(uint8_t *dst, const mp_int *a, int sz,
    uint32_t* abs_sign)
{
    int res;
    mp_int x;

    if (dst == NULL || a == NULL || sz < 0 || abs_sign == NULL)
        return BAD_FUNC_ARG;

    res = mp_init(&x);
    if (res == MP_OKAY) {
        /* make abs(x) and capture sign */
    #if defined(USE_FAST_MATH) || defined(USE_INTEGER_HEAP_MATH) || \
        ((defined(WOLFSSL_SP_MATH) || defined(WOLFSSL_SP_MATH_ALL)) && \
            defined(WOLFSSL_SP_INT_NEGATIVE))
        *abs_sign = a->sign;
    #else
        /* See companion comment in stm32_getabs_from_hexstr. sp_int
         * without WOLFSSL_SP_INT_NEGATIVE has no sign field; the mp_int
         * is the modular representative of `a` (e.g. P-256 Af = p-3,
         * a large positive integer). Default to POSITIVE so PKA reads
         * coef + sign self-consistently. Was incorrectly 1 (negative)
         * which made the V2 PKA ECCMul compute on a wrong curve and
         * hang/error; also caused the V1 PKA ECDSA sign+verify
         * roundtrip to fail on WL55. */
        *abs_sign = 0; /* positive */
    #endif
        res = mp_abs((mp_int*)a, &x);
        if (res == MP_OKAY)
            res = stm32_get_from_mp_int(dst, &x, sz);
        mp_clear(&x);
    }
    return res;
}

/* convert hex string to unsigned char */
static int stm32_getabs_from_hexstr(const char* hex, uint8_t* dst, int sz,
    uint32_t *abs_sign)
{
    int res;
    mp_int x;

    if (hex == NULL || dst == NULL || sz < 0)
        return BAD_FUNC_ARG;

    res = mp_init(&x);
    if (res == MP_OKAY) {
        res = mp_read_radix(&x, hex, MP_RADIX_HEX);
        /* optionally make abs(x) and capture sign */
        if (res == MP_OKAY && abs_sign != NULL) {
        #if defined(USE_FAST_MATH) || defined(USE_INTEGER_HEAP_MATH) || \
            ((defined(WOLFSSL_SP_MATH) || defined(WOLFSSL_SP_MATH_ALL)) && \
                defined(WOLFSSL_SP_INT_NEGATIVE))
            *abs_sign = x.sign;
        #else
            /* sp_int without WOLFSSL_SP_INT_NEGATIVE has no sign field;
             * mp_read_radix returns the absolute value as a positive
             * integer. The wolfssl ECC table stores the coefficient `a`
             * as its modular representative (e.g. P-256 Af = p-3, a
             * large positive number), so the sign here is POSITIVE
             * (a = +(p-3) which mod p equals -3 -- mathematically the
             * same as -3 with coefSign = negative, but the PKA expects
             * coef + coefSign to be self-consistent). Defaulting to 1
             * (negative) caused the PKA to compute on curve a=+3
             * instead of a=-3, producing R/S that don't verify against
             * the SW-generated pubkey. */
            *abs_sign = 0; /* positive */
        #endif
            res = mp_abs(&x, &x);
        }
        if (res == MP_OKAY)
            res = stm32_get_from_mp_int(dst, &x, sz);
        mp_clear(&x);
    }
    return res;
}
static int stm32_get_from_hexstr(const char* hex, uint8_t* dst, int sz)
{
    return stm32_getabs_from_hexstr(hex, dst, sz, NULL);
}

/* STM32 PKA supports up to 640-bit numbers; STM32_MAX_ECC_SIZE is defined in
 * wolfssl/wolfcrypt/port/st/stm32.h. */

#ifdef WOLFSSL_STM32_PKA_V2
/* find curve based on prime/modulus and return order/coefB */
static int stm32_get_curve_params(mp_int* modulus,
    uint8_t* order, uint8_t* coefB)
{
    int res, i, found = 0;
    mp_int modulusChk;
    res = mp_init(&modulusChk);
    if (res != MP_OKAY)
        return res;
    for (i = 0; ecc_sets[i].size != 0 && ecc_sets[i].name != NULL; i++) {
        const ecc_set_type* curve = &ecc_sets[i];
        /* match based on curve prime */
        if ((res = mp_read_radix(&modulusChk, curve->prime, MP_RADIX_HEX)) ==
                MP_OKAY && (mp_cmp(modulus, &modulusChk) == MP_EQ))
        {
            found = 1;
            if (order) {
                res = stm32_get_from_hexstr(curve->order, order, curve->size);
            }
            if (coefB) {
                res = stm32_get_from_hexstr(curve->Bf, coefB, curve->size);
            }
            break;
        }
    }
    mp_clear(&modulusChk);
    if (!found && res == MP_OKAY) {
        res = MP_RANGE;
    }
    return res;
}
#endif /* WOLFSSL_STM32_PKA_V2 */


/**
   Perform a point multiplication  (timing resistant)
   k    The scalar to multiply by
   G    The base point
   R    [out] Destination for kG
   a    ECC curve parameter a
   modulus  The modulus of the field the ECC curve is in
   order    curve order
   rng      Random Generator struct (not used)
   map      Boolean whether to map back to affine or not
                (1==map, 0 == leave in projective)
   return MP_OKAY on success
*/

/* The STM32H563 "light" PKA has no generic ECC scalar-mul mode -- only the
 * integrated ECDSA verify (mode 0x26). Under WC_STM32_PKA_VERIFY_ONLY,
 * keygen and (software) sign use the C ecc_mulmod from ecc.c, and only
 * stm32_ecc_verify_hash_ex below routes to the HW PKA. */
#if !defined(WC_STM32_PKA_VERIFY_ONLY)
int wc_ecc_mulmod_ex2(const mp_int* k, ecc_point *G, ecc_point *R, mp_int* a,
                      mp_int* modulus, mp_int* o, WC_RNG* rng, int map,
                      void* heap)
{
    PKA_ECCMulInTypeDef pka_mul;
    PKA_ECCMulOutTypeDef pka_mul_res;
    int szModulus;
    int status;
    int res;
    uint8_t Gxbin[STM32_MAX_ECC_SIZE];
    uint8_t Gybin[STM32_MAX_ECC_SIZE];
    uint8_t kbin[STM32_MAX_ECC_SIZE];
    uint8_t PtXbin[STM32_MAX_ECC_SIZE];
    uint8_t PtYbin[STM32_MAX_ECC_SIZE];
    uint8_t prime[STM32_MAX_ECC_SIZE];
    uint8_t coefA[STM32_MAX_ECC_SIZE];
#ifdef WOLFSSL_STM32_PKA_V2
    uint8_t coefB[STM32_MAX_ECC_SIZE];
    uint8_t order[STM32_MAX_ECC_SIZE];
#endif
    uint32_t coefA_sign = 1;

    (void)rng;

    XMEMSET(&pka_mul, 0x00, sizeof(PKA_ECCMulInTypeDef));
    XMEMSET(&pka_mul_res, 0x00, sizeof(PKA_ECCMulOutTypeDef));
    pka_mul_res.ptX = PtXbin;
    pka_mul_res.ptY = PtYbin;

    if (k == NULL || G == NULL || R == NULL || modulus == NULL) {
        return ECC_BAD_ARG_E;
    }

    szModulus = mp_unsigned_bin_size(modulus);

    res = stm32_get_from_mp_int(kbin, k, szModulus);
    if (res == MP_OKAY)
        res = stm32_get_from_mp_int(Gxbin, G->x, szModulus);
    if (res == MP_OKAY)
        res = stm32_get_from_mp_int(Gybin, G->y, szModulus);
    if (res == MP_OKAY)
        res = stm32_get_from_mp_int(prime, modulus, szModulus);
    if (res == MP_OKAY)
        res = stm32_getabs_from_mp_int(coefA, a, szModulus, &coefA_sign);
#ifdef WOLFSSL_STM32_PKA_V2
    XMEMSET(order, 0, sizeof(order));
    XMEMSET(coefB, 0, sizeof(coefB));
    if (res == MP_OKAY) {
        if (o != NULL) {
            /* use provided order and get coefB */
            res = stm32_get_from_mp_int(order, o, szModulus);
            if (res == MP_OKAY) {
                res = stm32_get_curve_params(modulus, NULL, coefB);
            }
        }
        else {
            /* get order and coefB for matching prime */
            res = stm32_get_curve_params(modulus, order, coefB);
        }
    }
#endif
    if (res != MP_OKAY) {
        ForceZero(kbin, sizeof(kbin));
        return res;
    }

    pka_mul.modulusSize = szModulus;
    pka_mul.coefSign = coefA_sign;
    pka_mul.coefA = coefA;
    pka_mul.modulus = prime;
    pka_mul.pointX = Gxbin;
    pka_mul.pointY = Gybin;
    pka_mul.scalarMulSize = szModulus;
    pka_mul.scalarMul = kbin;
#ifdef WOLFSSL_STM32_PKA_V2
    pka_mul.coefB = coefB;
    pka_mul.primeOrder = order;
#endif

    status = HAL_PKA_ECCMul(&hpka, &pka_mul, HAL_MAX_DELAY);
    if (status != HAL_OK) {
        ForceZero(kbin, sizeof(kbin));
        HAL_PKA_RAMReset(&hpka);
        return WC_HW_E;
    }
    pka_mul_res.ptX = Gxbin;
    pka_mul_res.ptY = Gybin;
    HAL_PKA_ECCMul_GetResult(&hpka, &pka_mul_res);
    ForceZero(kbin, sizeof(kbin));
    res = mp_read_unsigned_bin(R->x, Gxbin, szModulus);
    if (res == MP_OKAY) {
        res = mp_read_unsigned_bin(R->y, Gybin, szModulus);

#if defined(USE_FAST_MATH) || defined(USE_INTEGER_HEAP_MATH) || \
    ((defined(WOLFSSL_SP_MATH) || defined(WOLFSSL_SP_MATH_ALL)) && \
        defined(WOLFSSL_SP_INT_NEGATIVE))
        /* if k is negative, we compute the multiplication with abs(-k)
         * with result (x, y) and modify the result to (x, -y)
         */
        R->y->sign = k->sign;
#endif
    }
    if (res == MP_OKAY)
        res = mp_set(R->z, 1);
    HAL_PKA_RAMReset(&hpka);

    (void)heap;

    return res;
}

int wc_ecc_mulmod_ex(const mp_int *k, ecc_point *G, ecc_point *R, mp_int* a,
    mp_int *modulus, int map, void* heap)
{
    return wc_ecc_mulmod_ex2(k, G, R, a, modulus, NULL, NULL, map, heap);
}

int ecc_map_ex(ecc_point* P, mp_int* modulus, mp_digit mp, int ct)
{
    /* this is handled in hardware, so no projective mapping needed */
    (void)P;
    (void)modulus;
    (void)mp;
    (void)ct;
    return MP_OKAY;
}
#endif /* !WC_STM32_PKA_VERIFY_ONLY */

int stm32_ecc_verify_hash_ex(mp_int *r, mp_int *s, const byte* hash,
                    word32 hashlen, int* res, ecc_key* key)
{
    PKA_ECDSAVerifInTypeDef pka_ecc;
    int size;
    int status;
    uint8_t Rbin[STM32_MAX_ECC_SIZE];
    uint8_t Sbin[STM32_MAX_ECC_SIZE];
    uint8_t Qxbin[STM32_MAX_ECC_SIZE];
    uint8_t Qybin[STM32_MAX_ECC_SIZE];
    uint8_t Hashbin[STM32_MAX_ECC_SIZE];
    uint8_t prime[STM32_MAX_ECC_SIZE];
    uint8_t coefA[STM32_MAX_ECC_SIZE];
    uint8_t gen_x[STM32_MAX_ECC_SIZE];
    uint8_t gen_y[STM32_MAX_ECC_SIZE];
    uint8_t order[STM32_MAX_ECC_SIZE];
    uint32_t coefA_sign = 1;

    XMEMSET(&pka_ecc, 0x00, sizeof(PKA_ECDSAVerifInTypeDef));

    if (r == NULL || s == NULL || hash == NULL || res == NULL || key == NULL ||
            key->dp == NULL) {
        return ECC_BAD_ARG_E;
    }
    *res = 0; /* default to failure */
    size = wc_ecc_size(key); /* get key size in bytes */

    /* load R/S and public X/Y using key size */
    status = stm32_get_from_mp_int(Rbin, r, size);
    if (status == MP_OKAY)
        status = stm32_get_from_mp_int(Sbin, s, size);
    if (status == MP_OKAY)
        status = stm32_get_from_mp_int(Qxbin, key->pubkey.x, size);
    if (status == MP_OKAY)
        status = stm32_get_from_mp_int(Qybin, key->pubkey.y, size);
    if (status != MP_OKAY)
        return status;


    /* find parameters for the selected curve */
    status = stm32_get_from_hexstr(key->dp->prime, prime, size);
    if (status == MP_OKAY)
        status = stm32_get_from_hexstr(key->dp->order, order, size);
    if (status == MP_OKAY)
        status = stm32_get_from_hexstr(key->dp->Gx, gen_x, size);
    if (status == MP_OKAY)
        status = stm32_get_from_hexstr(key->dp->Gy, gen_y, size);
    if (status == MP_OKAY)
        status = stm32_getabs_from_hexstr(key->dp->Af, coefA, size,
                                          &coefA_sign);
    if (status != MP_OKAY)
        return status;

    pka_ecc.primeOrderSize =  size;
    pka_ecc.modulusSize =     size;
    pka_ecc.coefSign =        coefA_sign;
    pka_ecc.coef =            coefA;
    pka_ecc.modulus =         prime;
    pka_ecc.basePointX =      gen_x;
    pka_ecc.basePointY =      gen_y;
    pka_ecc.primeOrder =      order;
    pka_ecc.pPubKeyCurvePtX = Qxbin;
    pka_ecc.pPubKeyCurvePtY = Qybin;
    pka_ecc.RSign =           Rbin;
    pka_ecc.SSign =           Sbin;

    XMEMSET(Hashbin, 0, STM32_MAX_ECC_SIZE);
    if (hashlen > STM32_MAX_ECC_SIZE) {
        return ECC_BAD_ARG_E;
    }
    else if ((int)hashlen > size) {
        /* in the case that hashlen is larger than key size place hash at
         * beginning of buffer */
        XMEMCPY(Hashbin, hash, size);
    }
    else {
        /* in all other cases where hashlen is equal to or less than the key
         * size pad the Hashbin buffer with leading zero's */
        XMEMCPY(Hashbin + (size - hashlen), hash, hashlen);
    }
    pka_ecc.hash =            Hashbin;

    status = HAL_PKA_ECDSAVerif(&hpka, &pka_ecc, HAL_MAX_DELAY);
    if (status != HAL_OK) {
        HAL_PKA_RAMReset(&hpka);
        return WC_HW_E;
    }
    *res = HAL_PKA_ECDSAVerif_IsValidSignature(&hpka);
    HAL_PKA_RAMReset(&hpka);
    return status;
}

int stm32_ecc_sign_hash_ex(const byte* hash, word32 hashlen, WC_RNG* rng,
                     ecc_key* key, mp_int *r, mp_int *s)
{
    PKA_ECDSASignInTypeDef pka_ecc;
    PKA_ECDSASignOutTypeDef pka_ecc_out;
    int size;
    int status;
    mp_int gen_k;
    mp_int order_mp;
    uint8_t Keybin[STM32_MAX_ECC_SIZE];
    uint8_t Intbin[STM32_MAX_ECC_SIZE];
    uint8_t Rbin[STM32_MAX_ECC_SIZE];
    uint8_t Sbin[STM32_MAX_ECC_SIZE];
    uint8_t Hashbin[STM32_MAX_ECC_SIZE];
    uint8_t prime[STM32_MAX_ECC_SIZE];
    uint8_t coefA[STM32_MAX_ECC_SIZE];
#ifdef WOLFSSL_STM32_PKA_V2
    uint8_t coefB[STM32_MAX_ECC_SIZE];
#endif
    uint8_t gen_x[STM32_MAX_ECC_SIZE];
    uint8_t gen_y[STM32_MAX_ECC_SIZE];
    uint8_t order[STM32_MAX_ECC_SIZE];
    uint32_t coefA_sign = 1;

    XMEMSET(&pka_ecc, 0x00, sizeof(PKA_ECDSASignInTypeDef));
    XMEMSET(&pka_ecc_out, 0x00, sizeof(PKA_ECDSASignOutTypeDef));

    if (r == NULL || s == NULL || hash == NULL || key == NULL ||
            key->dp == NULL) {
        return ECC_BAD_ARG_E;
    }

    size = wc_ecc_size(key);

    /* find parameters for the selected curve */
    status = stm32_get_from_hexstr(key->dp->prime, prime, size);
    if (status == MP_OKAY)
        status = stm32_get_from_hexstr(key->dp->order, order, size);
    if (status == MP_OKAY)
        status = stm32_get_from_hexstr(key->dp->Gx, gen_x, size);
    if (status == MP_OKAY)
        status = stm32_get_from_hexstr(key->dp->Gy, gen_y, size);
    if (status == MP_OKAY)
        status = stm32_getabs_from_hexstr(key->dp->Af, coefA, size,
                                          &coefA_sign);
#ifdef WOLFSSL_STM32_PKA_V2
    if (status == MP_OKAY)
        status = stm32_get_from_hexstr(key->dp->Bf, coefB, size);
#endif
    if (status != MP_OKAY)
        return status;

    /* generate random part of "k" */
    mp_init(&gen_k);
    mp_init(&order_mp);
    status = mp_read_unsigned_bin(&order_mp, order, size);
    if (status == MP_OKAY)
        status = wc_ecc_gen_k(rng, size, &gen_k, &order_mp);
    if (status == MP_OKAY)
        status = stm32_get_from_mp_int(Intbin, &gen_k, size);
    mp_clear(&gen_k);
    mp_clear(&order_mp);
    if (status != MP_OKAY) {
        ForceZero(Intbin, sizeof(Intbin));
        return status;
     }

    /* get private part of "k" */
    status = stm32_get_from_mp_int(Keybin, wc_ecc_key_get_priv(key), size);
    if (status != MP_OKAY) {
        ForceZero(Keybin, sizeof(Keybin));
        ForceZero(Intbin, sizeof(Intbin));
        return status;
    }

    pka_ecc.primeOrderSize =  size;
    pka_ecc.modulusSize =     size;
    pka_ecc.coefSign =        coefA_sign;
    pka_ecc.coef =            coefA;
#ifdef WOLFSSL_STM32_PKA_V2
    pka_ecc.coefB =           coefB;
#endif
    pka_ecc.modulus =         prime;
    pka_ecc.basePointX =      gen_x;
    pka_ecc.basePointY =      gen_y;
    pka_ecc.primeOrder =      order;

    XMEMSET(Hashbin, 0, STM32_MAX_ECC_SIZE);
    if (hashlen > STM32_MAX_ECC_SIZE) {
        ForceZero(Keybin, sizeof(Keybin));
        ForceZero(Intbin, sizeof(Intbin));
        return ECC_BAD_ARG_E;
    }
    else if ((int)hashlen > size) {
        /* in the case that hashlen is larger than key size place hash at
         * beginning of buffer */
        XMEMCPY(Hashbin, hash, size);
    }
    else {
        /* in all other cases where hashlen is equal to or less than the key
         * size pad the Hashbin buffer with leading zero's */
        XMEMCPY(Hashbin + (size - hashlen), hash, hashlen);
    }
    pka_ecc.hash =            Hashbin;
    pka_ecc.integer =         Intbin;
    pka_ecc.privateKey =      Keybin;

    /* Assign R, S static buffers */
    pka_ecc_out.RSign = Rbin;
    pka_ecc_out.SSign = Sbin;

    status = HAL_PKA_ECDSASign(&hpka, &pka_ecc, HAL_MAX_DELAY);
    if (status != HAL_OK) {
        ForceZero(Keybin, sizeof(Keybin));
        ForceZero(Intbin, sizeof(Intbin));
        HAL_PKA_RAMReset(&hpka);
        return WC_HW_E;
    }
    HAL_PKA_ECDSASign_GetResult(&hpka, &pka_ecc_out, NULL);
    ForceZero(Keybin, sizeof(Keybin));
    ForceZero(Intbin, sizeof(Intbin));
    status = mp_read_unsigned_bin(r, pka_ecc_out.RSign, size);
    if (status == MP_OKAY)
        status = mp_read_unsigned_bin(s, pka_ecc_out.SSign, size);
    HAL_PKA_RAMReset(&hpka);
    return status;
}


#endif /* HAVE_ECC */
#endif /* WOLFSSL_STM32_PKA */
