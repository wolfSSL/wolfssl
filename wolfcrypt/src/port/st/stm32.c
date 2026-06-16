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

/* Number of word slots in the PKA RAM array (per the CMSIS device
 * header; e.g. 894 on WB55 V1). */
#define WC_STM32_PKA_RAM_WORDS \
    (sizeof(((PKA_TypeDef*)0)->RAM) / sizeof(((PKA_TypeDef*)0)->RAM[0]))

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
    return hpkah->Instance->RAM;
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
    uint32_t i;
    if (hpkah == NULL || hpkah->Instance == NULL) return;
    for (i = 0; i < WC_STM32_PKA_RAM_WORDS; i++) {
        hpkah->Instance->RAM[i] = 0UL;
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

/* #define DEBUG_STM32_HASH */

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
}

#endif /* WOLFSSL_DHUK || WOLFSSL_STM32_USE_SAES */



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

/* STM32 PKA supports up to 640-bit numbers */
#ifndef STM32_MAX_ECC_SIZE
#define STM32_MAX_ECC_SIZE (80)
#endif

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
