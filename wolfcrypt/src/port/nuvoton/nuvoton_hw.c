/* nuvoton_hw.c
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

/* The secure-world half of the M2354 port, and the only file in it that
 * includes a BSP header. Compiled when wolfCrypt runs secure, and on the
 * secure side of a TrustZone split where the veneers forward to it. Under
 * WOLFSSL_NUVOTON_NSC nothing here is built. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_NUVOTON_M2354) && defined(WOLFSSL_NUVOTON_SECURE)

/* BSP StdDriver. The application puts M2354BSP/Library/StdDriver/inc,
 * Library/Device/Nuvoton/M2354/Include and Library/CMSIS/Include on the
 * include path.
 *
 * This has to come before any wolfSSL header other than settings.h. M2354.h
 * defines TRUE and FALSE unconditionally as (1L) and (0L), while types.h
 * defines them as 1 and 0 behind an #ifndef. Whichever is second wins quietly
 * unless it is the BSP, which then redefines them and fails a -Werror build. */
#include "NuMicro.h"

#include "wolfcrypt/src/port/nuvoton/nuvoton_hw.h"

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#ifdef WOLFSSL_NUVOTON_CIPHER
    #include <wolfssl/wolfcrypt/aes.h>
#endif

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/* How many times wc_nuvoton_hw_init() has been called without a matching
 * wc_nuvoton_hw_cleanup(). The hardware comes up on the first and goes down on
 * the last, so several independent devices or a re-registration do not fight
 * over it. Guarded by the wolfCrypt hardware mutex. */
static int nuvotonRefCount = 0;

/* CRPT DMA reads and writes only word-aligned SRAM addresses. Nuvoton states
 * the requirement in the BSP's own mbedTLS layer
 * (Library/CryptoAccelerator/aes_alt.c): "(1) Word-aligned (2) Located in
 * 0x2xxxxxxx region."
 *
 * Both SRAM aliases have to be accepted, not just the one that note mentions.
 * On this part SRAM_BASE is 0x20000000 and NS_OFFSET is 0x10000000, so secure
 * code sees SRAM at 0x2xxxxxxx and non-secure code sees the same memory at
 * 0x3xxxxxxx, and the alias a transfer is given is what decides the security
 * attribute of the access. In a TrustZone build the buffers arriving through
 * the veneers are non-secure and therefore carry 0x3xxxxxxx addresses, which
 * are correct and must be passed to the engine as they are. Accepting only
 * 0x2xxxxxxx would make every AES and SHA call from the non-secure world
 * decline to software, silently and with no error to point at it.
 *
 * Note the polarity is the opposite way round from the NXP TrustZone parts,
 * where the 0x3xxxxxxx SRAM alias is the secure one. */
#define NUVOTON_DMA_REGION_MASK  0xF0000000u
#define NUVOTON_DMA_REGION_S     0x20000000u  /* SRAM_BASE */
#define NUVOTON_DMA_REGION_NS    0x30000000u  /* SRAM_BASE + NS_OFFSET */

static int nuvoton_dma_ok(const void* p, word32 sz)
{
    uint32_t addr = (uint32_t)(uintptr_t)p;
    uint32_t region;

    if (sz == 0) {
        return 1;
    }
    if ((addr & 0x3u) != 0) {
        return 0;
    }

    region = addr & NUVOTON_DMA_REGION_MASK;
    if (region != NUVOTON_DMA_REGION_S && region != NUVOTON_DMA_REGION_NS) {
        return 0;
    }

    return 1;
}

#ifdef WOLFSSL_NUVOTON_KS

/* Map the port's Key Store selector onto the BSP KS_MEM_Type. The two enums
 * happen to agree, but the mapping is written out so a BSP renumbering shows
 * up here as a compile problem rather than as keys landing in the wrong
 * store. */
static int nuvoton_ks_mem(int keyMem, KS_MEM_Type* mem)
{
    switch (keyMem) {
        case WC_NUVOTON_KS_SRAM:
            *mem = KS_SRAM;
            break;
        case WC_NUVOTON_KS_FLASH:
            *mem = KS_FLASH;
            break;
        case WC_NUVOTON_KS_OTP:
            *mem = KS_OTP;
            break;
        default:
            return BAD_FUNC_ARG;
    }

    return 0;
}

#endif /* WOLFSSL_NUVOTON_KS */

int wc_nuvoton_hw_init(void)
{
    int ret = 0;

    ret = wolfSSL_CryptHwMutexInit();
    if (ret != 0) {
        return ret;
    }

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }

    if (nuvotonRefCount == 0) {
        SYS_UnlockReg();

        /* CRPT and the Key Store share the AHB clock domain; the TRNG has its
         * own on APB1 and RNG_Open() ungates it. */
        CLK_EnableModuleClock(CRPT_MODULE);
        CLK_EnableModuleClock(KS_MODULE);
        SYS_ResetModule(CRPT_RST);

        if (KS_Open() != 0) {
            WOLFSSL_MSG("Nuvoton: KS_Open failed");
            ret = WC_HW_E;
        }

        /* Brings the TRNG up and points the CRPT PRNG seed generator at it. */
        if (ret == 0 && RNG_Open() != 0) {
            WOLFSSL_MSG("Nuvoton: RNG_Open failed");
            ret = WC_HW_E;
        }

        /* Arm the ECC interrupt sources in the accelerator itself. The BSP's
         * public key routines block on a flag that only ECC_DriverISR() sets,
         * and nothing in the driver enables ECCIEN/ECCEIEN - enabling the NVIC
         * line alone is not enough, because the CRPT never raises it. Without
         * this every ECC call spins out TIMEOUT_ECC, which is SystemCoreClock
         * iterations, and then fails. Nothing hangs and nothing reports the
         * cause; the test suite simply appears to stop making progress.
         *
         * The AES, SHA and RSA paths here poll INTSTS directly and do not need
         * an interrupt, so only ECC is armed. */
        if (ret == 0) {
            ECC_ENABLE_INT(CRPT);
        }

        SYS_LockReg();

        if (ret != 0) {
            CLK_DisableModuleClock(KS_MODULE);
            CLK_DisableModuleClock(CRPT_MODULE);
        }
    }

    if (ret == 0) {
        nuvotonRefCount++;
    }

    wolfSSL_CryptHwMutexUnLock();

    return ret;
}

void wc_nuvoton_hw_cleanup(void)
{
    if (wolfSSL_CryptHwMutexLock() != 0) {
        return;
    }

    if (nuvotonRefCount > 0) {
        nuvotonRefCount--;

        if (nuvotonRefCount == 0) {
            ECC_DISABLE_INT(CRPT);
            SYS_UnlockReg();
            SYS_ResetModule(CRPT_RST);
            CLK_DisableModuleClock(KS_MODULE);
            CLK_DisableModuleClock(CRPT_MODULE);
            SYS_LockReg();
        }
    }

    wolfSSL_CryptHwMutexUnLock();
}

#ifdef WOLFSSL_NUVOTON_TRNG

int wc_nuvoton_hw_trng(byte* out, word32 sz)
{
    int      ret = 0;
    int      got;
    word32   chunk;
    /* RNG_Random() fills whole words and hands back at most eight of them per
     * call, so a partial word at the tail is taken from a staging word rather
     * than written past the caller's buffer. */
    uint32_t buf[8];

    if (out == NULL || sz == 0) {
        return BAD_FUNC_ARG;
    }

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }

    while (sz > 0) {
        chunk = sz;
        if (chunk > sizeof(buf)) {
            chunk = (word32)sizeof(buf);
        }

        /* RNG_Random() returns the number of words it produced, and zero when
         * it timed out waiting on the engine. It is not a signed error. */
        got = RNG_Random(buf, (int32_t)((chunk + 3) / 4));
        if (got <= 0) {
            WOLFSSL_MSG("Nuvoton: RNG_Random failed");
            ret = RNG_FAILURE_E;
            break;
        }

        if (chunk > (word32)got * 4) {
            chunk = (word32)got * 4;
        }

        XMEMCPY(out, buf, chunk);
        out += chunk;
        sz  -= chunk;
    }

    ForceZero(buf, sizeof(buf));

    wolfSSL_CryptHwMutexUnLock();

    return ret;
}

#endif /* WOLFSSL_NUVOTON_TRNG */


#ifdef WOLFSSL_NUVOTON_HASH

/* Map the port's hash selector onto the BSP SHA_MODE_* value. */
static int nuvoton_sha_mode(int shaMode, uint32_t* opMode)
{
    switch (shaMode) {
        case WC_NUVOTON_SHA_1:
            *opMode = SHA_MODE_SHA1;
            break;
        case WC_NUVOTON_SHA_224:
            *opMode = SHA_MODE_SHA224;
            break;
        case WC_NUVOTON_SHA_256:
            *opMode = SHA_MODE_SHA256;
            break;
        case WC_NUVOTON_SHA_384:
            *opMode = SHA_MODE_SHA384;
            break;
        case WC_NUVOTON_SHA_512:
            *opMode = SHA_MODE_SHA512;
            break;
        default:
            return BAD_FUNC_ARG;
    }

    return 0;
}

int wc_nuvoton_hw_sha(wc_NuvotonShaReq* req)
{
    int      ret;
    uint32_t opMode = 0;
    uint32_t ctl;
    word32   timeout;
    /* SHA_Read() writes as many words as the current op mode produces, which
     * is sixteen for SHA-512 and fewer for the rest. */
    uint32_t dgst[16];

    if (req == NULL || req->fdbck == NULL) {
        return BAD_FUNC_ARG;
    }
    if (req->in == NULL && req->inSz > 0) {
        return BAD_FUNC_ARG;
    }
    if (req->last && (req->digest == NULL || req->digestSz == 0 ||
                      req->digestSz > sizeof(dgst))) {
        return BAD_FUNC_ARG;
    }

    ret = nuvoton_sha_mode(req->shaMode, &opMode);
    if (ret != 0) {
        return ret;
    }

    /* Both the message chunk and the feedback buffer are read and written by
     * DMA, so both have to satisfy the engine's addressing rules. */
    if (!nuvoton_dma_ok(req->in, req->inSz) ||
        !nuvoton_dma_ok(req->fdbck,
            WC_NUVOTON_SHA_FDBCK_WORDS * (word32)sizeof(word32))) {
        return BAD_ALIGN_E;
    }

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }

    /* FBIN pulls this context's saved state in before the block and FBOUT
     * writes the updated state back out after, both by DMA from FBADDR. That
     * pairing is what makes concurrent hash contexts safe: nothing of this
     * message stays in the engine between calls. The first chunk has no state
     * to read, and the last chunk has none worth writing. */
    ctl = (opMode << CRPT_HMAC_CTL_OPMODE_Pos) |
          CRPT_HMAC_CTL_INSWAP_Msk | CRPT_HMAC_CTL_OUTSWAP_Msk |
          CRPT_HMAC_CTL_DMACSCAD_Msk | CRPT_HMAC_CTL_DMAEN_Msk;

    if (req->first) {
        ctl |= CRPT_HMAC_CTL_DMAFIRST_Msk;
    }
    else {
        ctl |= CRPT_HMAC_CTL_FBIN_Msk;
    }

    if (req->last) {
        ctl |= CRPT_HMAC_CTL_DMALAST_Msk;
    }
    else {
        ctl |= CRPT_HMAC_CTL_FBOUT_Msk;
    }

    CRPT->HMAC_CTL     = ctl;
    CRPT->HMAC_FBADDR  = (uint32_t)(uintptr_t)req->fdbck;
    CRPT->HMAC_SADDR   = (uint32_t)(uintptr_t)req->in;
    CRPT->HMAC_DMACNT  = req->inSz;

    /* Clear the completion flag from whatever ran last, or the wait below
     * returns immediately. */
    CRPT->INTSTS = CRPT_INTSTS_HMACIF_Msk;

    CRPT->HMAC_CTL = ctl | CRPT_HMAC_CTL_START_Msk;

    /* Both conditions matter: the flag says a DMA round finished, and BUSY
     * says the engine has finished with it. */
    timeout = WOLFSSL_NUVOTON_HW_TIMEOUT;
    while (((CRPT->INTSTS & CRPT_INTSTS_HMACIF_Msk) == 0) ||
           ((CRPT->HMAC_STS & CRPT_HMAC_STS_BUSY_Msk) != 0)) {
        if (timeout-- == 0) {
            WOLFSSL_MSG("Nuvoton: SHA timeout");
            wolfSSL_CryptHwMutexUnLock();
            return WC_TIMEOUT_E;
        }
    }

    if ((CRPT->HMAC_STS & CRPT_HMAC_STS_DMAERR_Msk) != 0) {
        WOLFSSL_MSG("Nuvoton: SHA DMA error");
        CRPT->INTSTS = CRPT_INTSTS_HMACIF_Msk;
        wolfSSL_CryptHwMutexUnLock();
        return WC_HW_E;
    }

    CRPT->INTSTS = CRPT_INTSTS_HMACIF_Msk;

    if (req->last) {
        SHA_Read(CRPT, dgst);
        XMEMCPY(req->digest, dgst, req->digestSz);
        ForceZero(dgst, sizeof(dgst));
    }

    wolfSSL_CryptHwMutexUnLock();

    return 0;
}

#endif /* WOLFSSL_NUVOTON_HASH */


#ifdef WOLFSSL_NUVOTON_CIPHER

/* The engine reads and writes the key, the IV and the feedback registers as
 * words holding the wire bytes in memory order, with KINSWAP and the data
 * INSWAP/OUTSWAP bits doing the endianness. Same convention as the BSP's own
 * mbedTLS layer, so these two helpers are just an explicit spelling of the
 * byte copy it does. */
static uint32_t nuvoton_get32(const byte* p)
{
    return ((uint32_t)p[0])        | (((uint32_t)p[1]) <<  8) |
           (((uint32_t)p[2]) << 16) | (((uint32_t)p[3]) << 24);
}

/* Advance a 128-bit big-endian counter block by n. */
static void nuvoton_ctr_add(byte* ctr, word32 n)
{
    int    i;
    word32 carry = n;

    for (i = WC_AES_BLOCK_SIZE - 1; i >= 0 && carry != 0; i--) {
        carry += ctr[i];
        ctr[i] = (byte)carry;
        carry >>= 8;
    }
}

#ifdef WOLFSSL_NUVOTON_AESGCM
/* GCM loads its key words the other way up. See the KINSWAP note in
 * nuvoton_aes_gcm(). */
static uint32_t nuvoton_get32be(const byte* p)
{
    return (((uint32_t)p[0]) << 24) | (((uint32_t)p[1]) << 16) |
           (((uint32_t)p[2]) <<  8) |  ((uint32_t)p[3]);
}
#endif

static void nuvoton_set32(byte* p, uint32_t v)
{
    p[0] = (byte)(v      );
    p[1] = (byte)(v >>  8);
    p[2] = (byte)(v >> 16);
    p[3] = (byte)(v >> 24);
}

/* Staging for a request whose buffers do not meet the DMA addressing rules.
 * Placed in the default .bss, which the M2354 linker scripts put in the
 * 0x2xxxxxxx SRAM the engine can reach. nuvoton_aes_round() checks that before
 * using them, because a linker script that puts .bss somewhere the engine
 * cannot address would otherwise fail silently. Guarded by the hardware mutex
 * along with the engine itself. */
static ALIGN16 byte nuvotonDmaIn[WOLFSSL_NUVOTON_DMA_BUF_SZ];
static ALIGN16 byte nuvotonDmaOut[WOLFSSL_NUVOTON_DMA_BUF_SZ];

/* Map the port's AES selector onto the BSP AES_MODE_* value. */
static int nuvoton_aes_mode(int mode, uint32_t* opMode)
{
    switch (mode) {
        case WC_NUVOTON_AES_ECB:
            *opMode = AES_MODE_ECB;
            break;
        case WC_NUVOTON_AES_CBC:
            *opMode = AES_MODE_CBC;
            break;
        case WC_NUVOTON_AES_CTR:
            *opMode = AES_MODE_CTR;
            break;
        default:
            /* GCM and CCM do not come through here: they need the GCM packet
             * layout and the feedback buffer, not a plain DMA round. */
            return BAD_FUNC_ARG;
    }

    return 0;
}

/* Map a key length in bytes onto the BSP AES_KEY_SIZE_* value. */
static int nuvoton_aes_keysize(word32 keySz, uint32_t* keySize)
{
    switch (keySz) {
        case 16:
            *keySize = AES_KEY_SIZE_128;
            break;
        case 24:
            *keySize = AES_KEY_SIZE_192;
            break;
        case 32:
            *keySize = AES_KEY_SIZE_256;
            break;
        default:
            return BAD_FUNC_ARG;
    }

    return 0;
}

/* One DMA round over at most WOLFSSL_NUVOTON_DMA_BUF_SZ bytes. The caller has
 * the mutex and has already programmed the key; this sets the IV, runs the
 * round and leaves the chained IV in AES_FDBCK for the next one. */
static int nuvoton_aes_round(uint32_t ctl, const byte* in, byte* out,
    word32 sz, const uint32_t iv[4])
{
    word32      timeout;
    const byte* src = in;
    byte*       dst = out;

    /* Stage anything the engine cannot address itself. The staging buffers
     * are only useful if they are themselves reachable, which depends on where
     * the linker put .bss. */
    if (!nuvoton_dma_ok(in, sz)) {
        if (!nuvoton_dma_ok(nuvotonDmaIn, sizeof(nuvotonDmaIn))) {
            WOLFSSL_MSG("Nuvoton: DMA staging buffer is not engine addressable");
            return WC_HW_E;
        }
        XMEMCPY(nuvotonDmaIn, in, sz);
        src = nuvotonDmaIn;
    }
    if (!nuvoton_dma_ok(out, sz)) {
        if (!nuvoton_dma_ok(nuvotonDmaOut, sizeof(nuvotonDmaOut))) {
            WOLFSSL_MSG("Nuvoton: DMA staging buffer is not engine addressable");
            return WC_HW_E;
        }
        dst = nuvotonDmaOut;
    }

    CRPT->AES_CTL = ctl;

    AES_SetInitVect(CRPT, 0, iv);
    AES_SetDMATransfer(CRPT, 0, (uint32_t)(uintptr_t)src,
        (uint32_t)(uintptr_t)dst, sz);

    CRPT->INTSTS = CRPT_INTSTS_AESIF_Msk | CRPT_INTSTS_AESEIF_Msk;

    AES_Start(CRPT, 0, CRYPTO_DMA_ONE_SHOT);

    timeout = WOLFSSL_NUVOTON_HW_TIMEOUT;
    while ((CRPT->INTSTS &
            (CRPT_INTSTS_AESIF_Msk | CRPT_INTSTS_AESEIF_Msk)) == 0) {
        if (timeout-- == 0) {
            WOLFSSL_MSG("Nuvoton: AES timeout");
            return WC_TIMEOUT_E;
        }
    }

    if ((CRPT->INTSTS & CRPT_INTSTS_AESEIF_Msk) != 0) {
        WOLFSSL_MSG("Nuvoton: AES error interrupt");
        CRPT->INTSTS = CRPT_INTSTS_AESIF_Msk | CRPT_INTSTS_AESEIF_Msk;
        return WC_HW_E;
    }

    CRPT->INTSTS = CRPT_INTSTS_AESIF_Msk | CRPT_INTSTS_AESEIF_Msk;

    if (dst != out) {
        XMEMCPY(out, nuvotonDmaOut, sz);
    }

    return 0;
}


#if defined(WOLFSSL_NUVOTON_AESGCM) || defined(WOLFSSL_NUVOTON_AESCCM)

/* Packed AEAD packet staging, shared by GCM and CCM under the hardware mutex.
 * Sets where GCM switches from one round to the DMA cascade; CCM has no
 * cascade and is declined above this size. */
#ifndef WOLFSSL_NUVOTON_GCM_BUF_SZ
    #define WOLFSSL_NUVOTON_GCM_BUF_SZ 1088
#endif

static ALIGN16 byte nuvotonGcmIn[WOLFSSL_NUVOTON_GCM_BUF_SZ];
static ALIGN16 byte nuvotonGcmOut[WOLFSSL_NUVOTON_GCM_BUF_SZ];

#ifdef WOLFSSL_NUVOTON_AESGCM
/* GCM feedback state between cascade rounds, as the hash path carries
 * HMAC_FDBCK. 72 bytes, the size the vendor layer uses. */
static ALIGN16 byte nuvotonGcmFb[72];
#endif

/* DMA targets for the recomputed tag: the GHASH result, and the counter block
 * that encrypts it. */
static ALIGN16 byte nuvotonGcmGhash[WC_AES_BLOCK_SIZE];
static ALIGN16 byte nuvotonGcmTag[WC_AES_BLOCK_SIZE];

/* Round up to the next whole block. */
static word32 nuvoton_gcm_align(word32 sz)
{
    return (sz + (WC_AES_BLOCK_SIZE - 1)) & ~(word32)(WC_AES_BLOCK_SIZE - 1);
}

/* One AES round for GCM and CCM. Caller holds the mutex and has set the key
 * and the counts. */
static int nuvoton_gcm_run_dma(uint32_t ctl, const byte* src, byte* dst,
    word32 sz, uint32_t dmaMode)
{
    word32 timeout;

    CRPT->AES_CTL = ctl;
    AES_SetDMATransfer(CRPT, 0, (uint32_t)(uintptr_t)src,
        (uint32_t)(uintptr_t)dst, sz);

    CRPT->INTSTS = CRPT_INTSTS_AESIF_Msk | CRPT_INTSTS_AESEIF_Msk;
    AES_Start(CRPT, 0, dmaMode);

    timeout = WOLFSSL_NUVOTON_HW_TIMEOUT;
    while ((CRPT->INTSTS &
            (CRPT_INTSTS_AESIF_Msk | CRPT_INTSTS_AESEIF_Msk)) == 0) {
        if (timeout-- == 0) {
            WOLFSSL_MSG("Nuvoton: AES-GCM timeout");
            return WC_TIMEOUT_E;
        }
    }

    if ((CRPT->INTSTS & CRPT_INTSTS_AESEIF_Msk) != 0) {
        WOLFSSL_MSG("Nuvoton: AES-GCM error interrupt");
        CRPT->INTSTS = CRPT_INTSTS_AESIF_Msk | CRPT_INTSTS_AESEIF_Msk;
        return WC_HW_E;
    }

    CRPT->INTSTS = CRPT_INTSTS_AESIF_Msk | CRPT_INTSTS_AESEIF_Msk;

    return 0;
}

/* The common case: the whole operation in one round. */
static int nuvoton_gcm_run(uint32_t ctl, const byte* src, byte* dst, word32 sz)
{
    return nuvoton_gcm_run_dma(ctl, src, dst, sz, CRYPTO_DMA_ONE_SHOT);
}

#endif /* WOLFSSL_NUVOTON_AESGCM || WOLFSSL_NUVOTON_AESCCM */

#ifdef WOLFSSL_NUVOTON_AESGCM

/* Packed size: IV section, then AAD, then payload, each padded to a block. A
 * 96 bit IV takes one block with a trailing 1 (the J0 rule); any other length
 * is padded and followed by a block holding its bit count. */
static word32 nuvoton_gcm_packed_sz(word32 ivSz, word32 aadSz, word32 sz)
{
    word32 packed;

    if (ivSz == GCM_NONCE_MID_SZ) {
        packed = WC_AES_BLOCK_SIZE;
    }
    else {
        packed = nuvoton_gcm_align(ivSz) + WC_AES_BLOCK_SIZE;
    }

    return packed + nuvoton_gcm_align(aadSz) + nuvoton_gcm_align(sz);
}

/* Lay the three sections out for the engine. */
static void nuvoton_gcm_pack(const wc_NuvotonAesReq* req, byte* buf)
{
    word32 off = 0;
    word64 bits;
    word32 i;

    XMEMCPY(buf, req->iv, req->ivSz);

    if (req->ivSz == GCM_NONCE_MID_SZ) {
        XMEMSET(buf + req->ivSz, 0, WC_AES_BLOCK_SIZE - req->ivSz);
        buf[WC_AES_BLOCK_SIZE - 1] = 1;
        off = WC_AES_BLOCK_SIZE;
    }
    else {
        off = nuvoton_gcm_align(req->ivSz);
        XMEMSET(buf + req->ivSz, 0, off - req->ivSz);

        /* 64 bits of zero, then the IV length in bits, big endian. */
        XMEMSET(buf + off, 0, WC_AES_BLOCK_SIZE);
        bits = (word64)req->ivSz * 8;
        for (i = 0; i < 8; i++) {
            buf[off + WC_AES_BLOCK_SIZE - 1 - i] = (byte)(bits >> (i * 8));
        }
        off += WC_AES_BLOCK_SIZE;
    }

    if (req->aadSz > 0) {
        XMEMCPY(buf + off, req->aad, req->aadSz);
        XMEMSET(buf + off + req->aadSz,
            0, nuvoton_gcm_align(req->aadSz) - req->aadSz);
        off += nuvoton_gcm_align(req->aadSz);
    }

    if (req->sz > 0) {
        XMEMCPY(buf + off, req->in, req->sz);
        XMEMSET(buf + off + req->sz, 0, nuvoton_gcm_align(req->sz) - req->sz);
    }
}

/* Write a 64 bit big-endian bit count. */
static void nuvoton_gcm_bitlen(byte* p, word32 bytes)
{
    word64 bits = (word64)bytes * 8;
    word32 i;

    for (i = 0; i < 8; i++) {
        p[7 - i] = (byte)(bits >> (i * 8));
    }
}

/* T = CTR(J0, GHASH(align(A) || align(C) || bitlen(A) || bitlen(C))), on the
 * engine in GHASH and CTR mode with the key already loaded. Used for the two
 * payload lengths whose tag the engine gets wrong. The vendor layer does this
 * for encrypt only, leaving its decrypt checking a tag it knows to be wrong.
 * Caller holds the mutex. */
static int nuvoton_gcm_tag(wc_NuvotonAesReq* req, const byte* cipher,
    uint32_t keySize)
{
    uint32_t ctl;
    uint32_t j0[4];
    word32   aadSection;
    word32   cSection;
    word32   len;
    word32   i;
    int      ret;

    aadSection = nuvoton_gcm_align(req->aadSz);
    cSection   = nuvoton_gcm_align(req->sz);
    len        = aadSection + cSection + WC_AES_BLOCK_SIZE;

    if (len > (word32)sizeof(nuvotonGcmIn)) {
        return BAD_LENGTH_E;
    }

    /* GHASH input: the AAD and the ciphertext, each padded to a block, then
     * one block holding both bit counts. */
    XMEMSET(nuvotonGcmIn, 0, len);
    if (req->aadSz > 0) {
        XMEMCPY(nuvotonGcmIn, req->aad, req->aadSz);
    }
    if (req->sz > 0) {
        XMEMCPY(nuvotonGcmIn + aadSection, cipher, req->sz);
    }
    nuvoton_gcm_bitlen(nuvotonGcmIn + aadSection + cSection, req->aadSz);
    nuvoton_gcm_bitlen(nuvotonGcmIn + aadSection + cSection + 8, req->sz);

    ctl = CRPT_AES_CTL_ENCRPT_Msk |
          (keySize << CRPT_AES_CTL_KEYSZ_Pos) |
          (AES_IN_OUT_SWAP << CRPT_AES_CTL_OUTSWAP_Pos) |
          CRPT_AES_CTL_DMAEN_Msk;

    ret = nuvoton_gcm_run(ctl | (AES_MODE_GHASH << CRPT_AES_CTL_OPMODE_Pos),
        nuvotonGcmIn, nuvotonGcmGhash, len);
    if (ret != 0) {
        return ret;
    }

    /* J0: a 96 bit nonce is used directly with a counter of one, anything else
     * is itself a GHASH. */
    if (req->ivSz == GCM_NONCE_MID_SZ) {
        for (i = 0; i < 3; i++) {
            j0[i] = (((uint32_t)req->iv[i * 4    ]) << 24) |
                    (((uint32_t)req->iv[i * 4 + 1]) << 16) |
                    (((uint32_t)req->iv[i * 4 + 2]) <<  8) |
                     ((uint32_t)req->iv[i * 4 + 3]);
        }
        j0[3] = 1;
    }
    else {
        len = nuvoton_gcm_align(req->ivSz) + WC_AES_BLOCK_SIZE;
        if (len > (word32)sizeof(nuvotonGcmIn)) {
            return BAD_LENGTH_E;
        }

        XMEMSET(nuvotonGcmIn, 0, len);
        XMEMCPY(nuvotonGcmIn, req->iv, req->ivSz);
        nuvoton_gcm_bitlen(nuvotonGcmIn + len - 8, req->ivSz);

        ret = nuvoton_gcm_run(
            ctl | (AES_MODE_GHASH << CRPT_AES_CTL_OPMODE_Pos),
            nuvotonGcmIn, nuvotonGcmTag, len);
        if (ret != 0) {
            return ret;
        }

        for (i = 0; i < 4; i++) {
            j0[i] = (((uint32_t)nuvotonGcmTag[i * 4    ]) << 24) |
                    (((uint32_t)nuvotonGcmTag[i * 4 + 1]) << 16) |
                    (((uint32_t)nuvotonGcmTag[i * 4 + 2]) <<  8) |
                     ((uint32_t)nuvotonGcmTag[i * 4 + 3]);
        }
    }

    AES_SetInitVect(CRPT, 0, j0);

    ret = nuvoton_gcm_run(ctl | (AES_MODE_CTR << CRPT_AES_CTL_OPMODE_Pos),
        nuvotonGcmGhash, nuvotonGcmTag, WC_AES_BLOCK_SIZE);
    if (ret == 0) {
        XMEMCPY(req->tag, nuvotonGcmTag, req->tagSz);
    }

    return ret;
}

/* GCM too large for one round: the IV and AAD first, then payload chunks, with
 * the feedback state swapped through AES_FBADDR. The tag follows the last
 * chunk's padded output. Caller holds the mutex and has set the key. */
static int nuvoton_gcm_cascade(wc_NuvotonAesReq* req, uint32_t ctl)
{
    word32 chunkMax;
    word32 done;
    word32 chunk;
    word32 chunkAligned = 0;
    word32 headSz;
    int    ret;

    /* Round one carries the IV and AAD, so the chunk buffer has to hold them
     * as well as a payload chunk. */
    headSz = nuvoton_gcm_packed_sz(req->ivSz, req->aadSz, 0);
    if (headSz + WC_AES_BLOCK_SIZE > (word32)sizeof(nuvotonGcmIn)) {
        return BAD_LENGTH_E;
    }

    chunkMax = (word32)sizeof(nuvotonGcmIn);
    if (chunkMax > (word32)sizeof(nuvotonGcmOut) - WC_AES_BLOCK_SIZE) {
        chunkMax = (word32)sizeof(nuvotonGcmOut) - WC_AES_BLOCK_SIZE;
    }
    chunkMax &= ~(word32)(WC_AES_BLOCK_SIZE - 1);

    XMEMSET(nuvotonGcmFb, 0, sizeof(nuvotonGcmFb));
    CRPT->AES_FBADDR = (uint32_t)(uintptr_t)nuvotonGcmFb;

    /* IV and AAD first, feedback state out. */
    {
        wc_NuvotonAesReq head = *req;

        head.sz = 0;
        nuvoton_gcm_pack(&head, nuvotonGcmIn);
    }

    ret = nuvoton_gcm_run_dma(ctl | CRPT_AES_CTL_FBOUT_Msk, nuvotonGcmIn,
        nuvotonGcmOut, headSz, CRYPTO_DMA_FIRST);

    for (done = 0; ret == 0 && done < req->sz; done += chunk) {
        chunk = req->sz - done;
        if (chunk > chunkMax) {
            chunk = chunkMax;
        }

        XMEMCPY(nuvotonGcmIn, req->in + done, chunk);
        chunkAligned = nuvoton_gcm_align(chunk);
        if (chunkAligned > chunk) {
            XMEMSET(nuvotonGcmIn + chunk, 0, chunkAligned - chunk);
        }

        ret = nuvoton_gcm_run_dma(
            ctl | CRPT_AES_CTL_FBIN_Msk | CRPT_AES_CTL_FBOUT_Msk,
            nuvotonGcmIn, nuvotonGcmOut, chunkAligned,
            ((done + chunk) >= req->sz) ? CRYPTO_DMA_LAST :
                                          CRYPTO_DMA_CONTINUE);
        if (ret == 0) {
            XMEMCPY(req->out + done, nuvotonGcmOut, chunk);
        }
    }

    if (ret == 0) {
        /* The tag lands after the last chunk's padded output. */
        XMEMCPY(req->tag, nuvotonGcmOut + chunkAligned, req->tagSz);
    }

    return ret;
}

/* One-shot AES-GCM. Encrypt and decrypt run the identical packet through the
 * engine, differing only in CRPT_AES_CTL_ENCRPT_Msk. The tag follows the
 * payload either way, and on decrypt the caller compares it. */
static int nuvoton_aes_gcm(wc_NuvotonAesReq* req)
{
    uint32_t keyWords[8];
    uint32_t keySize = 0;
    uint32_t ctl;
    word32   packedSz;
    word32   outSz;
    word32   i;
    int      oneShot;
    int      ret;

    if (req->iv == NULL || req->ivSz == 0) {
        return BAD_FUNC_ARG;
    }
    if (req->tag == NULL || req->tagSz == 0 ||
            req->tagSz > WC_AES_BLOCK_SIZE) {
        return BAD_FUNC_ARG;
    }
    if ((req->aadSz > 0 && req->aad == NULL) ||
            (req->sz > 0 && (req->in == NULL || req->out == NULL))) {
        return BAD_FUNC_ARG;
    }

    ret = nuvoton_aes_keysize(req->keySz, &keySize);
    if (ret != 0) {
        return ret;
    }

    packedSz = nuvoton_gcm_packed_sz(req->ivSz, req->aadSz, req->sz);
    outSz    = nuvoton_gcm_align(req->sz) + WC_AES_BLOCK_SIZE;

    /* Everything that fits goes in one round; anything larger goes through the
     * cascade, which has no size limit of its own. */
    oneShot = (packedSz <= (word32)sizeof(nuvotonGcmIn) &&
               outSz    <= (word32)sizeof(nuvotonGcmOut));

    XMEMSET(keyWords, 0, sizeof(keyWords));
    if (req->key != NULL) {
        for (i = 0; i < req->keySz; i += 4) {
            keyWords[i / 4] = nuvoton_get32be(req->key + i);
        }
    }

    /* No KINSWAP, unlike every other mode: the key words above are big endian
     * and go in as they are. The wrong pairing gives a plausible ciphertext
     * and a wrong tag. */
    ctl = ((uint32_t)req->encrypt << CRPT_AES_CTL_ENCRPT_Pos) |
          (AES_MODE_GCM << CRPT_AES_CTL_OPMODE_Pos) |
          (keySize      << CRPT_AES_CTL_KEYSZ_Pos)  |
          (AES_IN_OUT_SWAP << CRPT_AES_CTL_OUTSWAP_Pos) |
          CRPT_AES_CTL_DMAEN_Msk;

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        ForceZero(keyWords, sizeof(keyWords));
        return ret;
    }

    if (oneShot) {
        nuvoton_gcm_pack(req, nuvotonGcmIn);
        XMEMSET(nuvotonGcmOut, 0, outSz);
    }

    /* GCM state survives a mode change, so reset first as the BSP does. The
     * reset also clears the ECC interrupt enables set at init, so re-arm
     * them or every later ECC call spins out its timeout. */
    SYS_UnlockReg();
    SYS_ResetModule(CRPT_RST);
    ECC_ENABLE_INT(CRPT);
    SYS_LockReg();

    if (req->keySlot == WC_NUVOTON_NO_SLOT) {
        AES_SetKey(CRPT, 0, keyWords, keySize);
    }
    else {
#ifdef WOLFSSL_NUVOTON_KS
        KS_MEM_Type mem;

        ret = nuvoton_ks_mem(req->keyMem, &mem);
        if (ret == 0) {
            AES_SetKey_KS(CRPT, mem, (int32_t)req->keySlot);
        }
#else
        ret = BAD_FUNC_ARG;
#endif
    }

    if (ret == 0) {
        /* Byte counts, not block counts, and the unpadded ones. */
        CRPT->AES_GCM_IVCNT[0] = req->ivSz;
        CRPT->AES_GCM_IVCNT[1] = 0;
        CRPT->AES_GCM_ACNT[0]  = req->aadSz;
        CRPT->AES_GCM_ACNT[1]  = 0;
        CRPT->AES_GCM_PCNT[0]  = req->sz;
        CRPT->AES_GCM_PCNT[1]  = 0;

        if (oneShot) {
            ret = nuvoton_gcm_run(ctl, nuvotonGcmIn, nuvotonGcmOut, packedSz);
        }
        else {
            ret = nuvoton_gcm_cascade(req, ctl);
        }
    }

    if (ret == 0) {
        if (oneShot) {
            if (req->sz > 0) {
                XMEMCPY(req->out, nuvotonGcmOut, req->sz);
            }
            /* The tag follows the padded payload. */
            XMEMCPY(req->tag, nuvotonGcmOut + nuvoton_gcm_align(req->sz),
                req->tagSz);
        }

        /* Except for the two payload lengths the engine gets wrong, where the
         * tag is recomputed from the ciphertext - which on encrypt is what was
         * just produced, and on decrypt is the input. */
        if ((req->sz % WC_AES_BLOCK_SIZE) == 1 ||
                (req->sz % WC_AES_BLOCK_SIZE) == 15) {
            ret = nuvoton_gcm_tag(req,
                req->encrypt ? req->out : req->in, keySize);
        }
    }

    CRPT->AES_CTL = CRPT_AES_CTL_STOP_Msk;

    ForceZero(keyWords, sizeof(keyWords));
    ForceZero(nuvotonGcmIn, sizeof(nuvotonGcmIn));
    ForceZero(nuvotonGcmOut, sizeof(nuvotonGcmOut));
    ForceZero(nuvotonGcmGhash, sizeof(nuvotonGcmGhash));
    ForceZero(nuvotonGcmTag, sizeof(nuvotonGcmTag));
#ifdef WOLFSSL_NUVOTON_AESGCM
    ForceZero(nuvotonGcmFb, sizeof(nuvotonGcmFb));
#endif

    wolfSSL_CryptHwMutexUnLock();

    return ret;
}

#endif /* WOLFSSL_NUVOTON_AESGCM */


#ifdef WOLFSSL_NUVOTON_AESCCM

/* CCM shares the GCM staging buffers: both are one packed packet in, payload
 * and tag out, and the hardware mutex serialises them. */

/* CCM B0: flags | nonce | payload length big endian in the trailing q bytes,
 * flags carrying AAD presence, tag length and q. SP 800-38C A.2. */
static void nuvoton_ccm_b0(const wc_NuvotonAesReq* req, byte q, byte* b0)
{
    word32 len = req->sz;
    byte   i;

    XMEMSET(b0, 0, WC_AES_BLOCK_SIZE);

    b0[0] = (byte)(((req->aadSz > 0) ? 0x40 : 0x00) |
                   ((((byte)req->tagSz - 2) / 2) << 3) |
                   (byte)(q - 1));
    XMEMCPY(b0 + 1, req->iv, req->ivSz);

    for (i = 0; i < q; i++) {
        b0[WC_AES_BLOCK_SIZE - 1 - i] = (byte)len;
        len >>= 8;
    }
}

/* One-shot AES-CCM. Key words go in little endian with KINSWAP set, as the
 * block modes load them - not the GCM convention. */
static int nuvoton_aes_ccm(wc_NuvotonAesReq* req)
{
    uint32_t keyWords[8];
    uint32_t ctr[4];
    uint32_t keySize = 0;
    uint32_t ctl;
    byte     ctr0[WC_AES_BLOCK_SIZE];
    byte     q;
    word32   aadSection;
    word32   pSection;
    word32   packedSz;
    word32   i;
    int      ret;

    if (req->iv == NULL || req->ivSz < 7 || req->ivSz > 13) {
        return BAD_FUNC_ARG;
    }
    if (req->tag == NULL || req->tagSz < 4 || req->tagSz > WC_AES_BLOCK_SIZE ||
            (req->tagSz % 2) != 0) {
        return BAD_FUNC_ARG;
    }
    if (req->aadSz >= 0xFF00) {
        /* The AAD length is encoded in the two bytes ahead of it here, which
         * is the short form only. */
        return BAD_LENGTH_E;
    }
    if ((req->aadSz > 0 && req->aad == NULL) ||
            (req->sz > 0 && (req->in == NULL || req->out == NULL))) {
        return BAD_FUNC_ARG;
    }

    ret = nuvoton_aes_keysize(req->keySz, &keySize);
    if (ret != 0) {
        return ret;
    }

    q = (byte)(15 - req->ivSz);

    /* B0, then the AAD with its two length bytes, then the payload. With no
     * AAD there is no AAD block at all - B0's flags say so and the MAC covers
     * B0 and the payload only. The vendor layer emits one regardless, which
     * authenticates a block the standard does not have. */
    aadSection = (req->aadSz > 0) ? nuvoton_gcm_align(req->aadSz + 2) : 0;
    pSection   = nuvoton_gcm_align(req->sz);
    packedSz   = WC_AES_BLOCK_SIZE + aadSection + pSection;

    if (packedSz > (word32)sizeof(nuvotonGcmIn) ||
            (pSection + WC_AES_BLOCK_SIZE) > (word32)sizeof(nuvotonGcmOut)) {
        return BAD_LENGTH_E;
    }

    XMEMSET(keyWords, 0, sizeof(keyWords));
    if (req->key != NULL) {
        for (i = 0; i < req->keySz; i += 4) {
            keyWords[i / 4] = nuvoton_get32(req->key + i);
        }
    }

    /* Ctr0, the counter the tag is masked with: starts at zero, not at the
     * one the payload blocks begin from. */
    XMEMSET(ctr0, 0, sizeof(ctr0));
    ctr0[0] = (byte)(q - 1);
    XMEMCPY(ctr0 + 1, req->iv, req->ivSz);
    for (i = 0; i < WC_AES_BLOCK_SIZE; i += 4) {
        ctr[i / 4] = nuvoton_get32(ctr0 + i);
    }

    ctl = ((uint32_t)req->encrypt << CRPT_AES_CTL_ENCRPT_Pos) |
          (AES_MODE_CCM << CRPT_AES_CTL_OPMODE_Pos) |
          (keySize      << CRPT_AES_CTL_KEYSZ_Pos)  |
          (AES_IN_OUT_SWAP << CRPT_AES_CTL_OUTSWAP_Pos) |
          CRPT_AES_CTL_KINSWAP_Msk |
          CRPT_AES_CTL_DMAEN_Msk;

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        ForceZero(keyWords, sizeof(keyWords));
        return ret;
    }

    XMEMSET(nuvotonGcmIn, 0, packedSz);
    nuvoton_ccm_b0(req, q, nuvotonGcmIn);

    if (req->aadSz > 0) {
        /* The AAD length, big endian, ahead of the AAD itself. */
        nuvotonGcmIn[WC_AES_BLOCK_SIZE]     = (byte)(req->aadSz >> 8);
        nuvotonGcmIn[WC_AES_BLOCK_SIZE + 1] = (byte)(req->aadSz);
        XMEMCPY(nuvotonGcmIn + WC_AES_BLOCK_SIZE + 2, req->aad, req->aadSz);
    }
    if (req->sz > 0) {
        XMEMCPY(nuvotonGcmIn + WC_AES_BLOCK_SIZE + aadSection, req->in,
            req->sz);
    }
    XMEMSET(nuvotonGcmOut, 0, pSection + WC_AES_BLOCK_SIZE);

    SYS_UnlockReg();
    SYS_ResetModule(CRPT_RST);
    ECC_ENABLE_INT(CRPT);
    SYS_LockReg();

    if (req->keySlot == WC_NUVOTON_NO_SLOT) {
        AES_SetKey(CRPT, 0, keyWords, keySize);
    }
    else {
#ifdef WOLFSSL_NUVOTON_KS
        KS_MEM_Type mem;

        ret = nuvoton_ks_mem(req->keyMem, &mem);
        if (ret == 0) {
            AES_SetKey_KS(CRPT, mem, (int32_t)req->keySlot);
        }
#else
        ret = BAD_FUNC_ARG;
#endif
    }

    if (ret == 0) {
        CRPT->AES_CTL = ctl;
        AES_SetInitVect(CRPT, 0, ctr);

        /* B0 and the AAD blocks are authenticated-only data to the engine. */
        CRPT->AES_GCM_ACNT[0] = WC_AES_BLOCK_SIZE + aadSection;
        CRPT->AES_GCM_ACNT[1] = 0;
        CRPT->AES_GCM_PCNT[0] = req->sz;
        CRPT->AES_GCM_PCNT[1] = 0;

        ret = nuvoton_gcm_run(ctl, nuvotonGcmIn, nuvotonGcmOut, packedSz);
    }

    if (ret == 0) {
        if (req->sz > 0) {
            XMEMCPY(req->out, nuvotonGcmOut, req->sz);
        }
        XMEMCPY(req->tag, nuvotonGcmOut + pSection, req->tagSz);
    }

    CRPT->AES_CTL = CRPT_AES_CTL_STOP_Msk;

    ForceZero(keyWords, sizeof(keyWords));
    ForceZero(ctr, sizeof(ctr));
    ForceZero(nuvotonGcmIn, sizeof(nuvotonGcmIn));
    ForceZero(nuvotonGcmOut, sizeof(nuvotonGcmOut));

    wolfSSL_CryptHwMutexUnLock();

    return ret;
}

#endif /* WOLFSSL_NUVOTON_AESCCM */

int wc_nuvoton_hw_aes(wc_NuvotonAesReq* req)
{
    int      ret;
    uint32_t opMode = 0;
    uint32_t keySize = 0;
    uint32_t ctl;
    uint32_t iv[4];
    uint32_t keyWords[8];
    byte     nextIv[WC_AES_BLOCK_SIZE];
    word32   done;
    word32   chunk;
    word32   i;

    if (req == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_NUVOTON_AESGCM
    /* GCM is a packed packet and a tag, not a run of whole blocks, and its
     * payload may be empty (GMAC). It gets its own path. */
    if (req->mode == WC_NUVOTON_AES_GCM) {
        return nuvoton_aes_gcm(req);
    }
#endif
#ifdef WOLFSSL_NUVOTON_AESCCM
    if (req->mode == WC_NUVOTON_AES_CCM) {
        return nuvoton_aes_ccm(req);
    }
#endif

    if (req->in == NULL || req->out == NULL) {
        return BAD_FUNC_ARG;
    }
    if (req->sz == 0 || (req->sz % WC_AES_BLOCK_SIZE) != 0) {
        return BAD_LENGTH_E;
    }
    if (req->keySlot == WC_NUVOTON_NO_SLOT && req->key == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = nuvoton_aes_mode(req->mode, &opMode);
    if (ret != 0) {
        return ret;
    }
    ret = nuvoton_aes_keysize(req->keySz, &keySize);
    if (ret != 0) {
        return ret;
    }
    if (req->mode != WC_NUVOTON_AES_ECB && req->iv == NULL) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(keyWords, 0, sizeof(keyWords));
    if (req->key != NULL) {
        for (done = 0; done < req->keySz; done += 4) {
            keyWords[done / 4] = nuvoton_get32(req->key + done);
        }
    }

    XMEMSET(iv, 0, sizeof(iv));
    if (req->iv != NULL) {
        for (done = 0; done < WC_AES_BLOCK_SIZE; done += 4) {
            iv[done / 4] = nuvoton_get32(req->iv + done);
        }
    }

    /* KINSWAP goes with the key words built above; INSWAP and OUTSWAP say the
     * message is little-endian in memory. */
    ctl = ((uint32_t)req->encrypt << CRPT_AES_CTL_ENCRPT_Pos) |
          (opMode  << CRPT_AES_CTL_OPMODE_Pos) |
          (keySize << CRPT_AES_CTL_KEYSZ_Pos)  |
          (AES_IN_OUT_SWAP << CRPT_AES_CTL_OUTSWAP_Pos) |
          CRPT_AES_CTL_KINSWAP_Msk |
          CRPT_AES_CTL_DMAEN_Msk;

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        ForceZero(keyWords, sizeof(keyWords));
        return ret;
    }

    /* Stop whatever the engine was doing, then load the key once: the CTL
     * writes below do not disturb the key registers. */
    CRPT->AES_CTL = CRPT_AES_CTL_STOP_Msk;

    if (req->keySlot == WC_NUVOTON_NO_SLOT) {
        AES_SetKey(CRPT, 0, keyWords, keySize);
    }
    else {
#ifdef WOLFSSL_NUVOTON_KS
        KS_MEM_Type mem;

        ret = nuvoton_ks_mem(req->keyMem, &mem);
        if (ret == 0) {
            /* The engine reads the key straight out of the store, so it never
             * appears in memory the CPU can see. */
            AES_SetKey_KS(CRPT, mem, (int32_t)req->keySlot);
        }
#else
        ret = BAD_FUNC_ARG;
#endif
    }

    for (done = 0; ret == 0 && done < req->sz; done += chunk) {
        chunk = req->sz - done;
        if (chunk > WOLFSSL_NUVOTON_DMA_BUF_SZ) {
            chunk = WOLFSSL_NUVOTON_DMA_BUF_SZ;
        }

        /* CBC decrypt chains on the ciphertext, which is the input, and in
         * and out are allowed to alias - so take the copy before the round
         * overwrites it. */
        if (req->mode == WC_NUVOTON_AES_CBC && !req->encrypt) {
            XMEMCPY(nextIv, req->in + done + chunk - WC_AES_BLOCK_SIZE,
                WC_AES_BLOCK_SIZE);
        }

        ret = nuvoton_aes_round(ctl, req->in + done, req->out + done, chunk,
            iv);
        if (ret != 0) {
            break;
        }

        /* Carry the chaining state to the next chunk, and to the next call.
         *
         * Derived from the data rather than read out of AES_FDBCK. FDBCK does
         * hold the engine's feedback, but the TRM describes it in terms of DMA
         * cascade mode and does not pin down its byte order relative to
         * AES_IV, and guessing wrong is not visible in a single-shot test -
         * the first block comes out right and only the next call is wrong.
         * The ciphertext and the counter are unambiguous and already in hand. */
        switch (req->mode) {
            case WC_NUVOTON_AES_CBC:
                if (req->encrypt) {
                    XMEMCPY(nextIv, req->out + done + chunk -
                        WC_AES_BLOCK_SIZE, WC_AES_BLOCK_SIZE);
                }
                for (i = 0; i < WC_AES_BLOCK_SIZE; i += 4) {
                    iv[i / 4] = nuvoton_get32(nextIv + i);
                }
                break;

            case WC_NUVOTON_AES_CTR:
                /* The counter is a big-endian integer over the whole block,
                 * advanced once per block the engine consumed. */
                for (i = 0; i < WC_AES_BLOCK_SIZE; i += 4) {
                    nuvoton_set32(nextIv + i, iv[i / 4]);
                }
                nuvoton_ctr_add(nextIv, chunk / WC_AES_BLOCK_SIZE);
                for (i = 0; i < WC_AES_BLOCK_SIZE; i += 4) {
                    iv[i / 4] = nuvoton_get32(nextIv + i);
                }
                break;

            default:
                /* ECB has no chaining state. */
                break;
        }
    }

    /* Hand the chained IV back so the next call continues the stream. */
    if (ret == 0 && req->iv != NULL) {
        for (done = 0; done < WC_AES_BLOCK_SIZE; done += 4) {
            nuvoton_set32(req->iv + done, iv[done / 4]);
        }
    }

    CRPT->AES_CTL = CRPT_AES_CTL_STOP_Msk;

    ForceZero(keyWords, sizeof(keyWords));
    ForceZero(nuvotonDmaIn, sizeof(nuvotonDmaIn));
    ForceZero(nuvotonDmaOut, sizeof(nuvotonDmaOut));

    wolfSSL_CryptHwMutexUnLock();

    return ret;
}


#endif /* WOLFSSL_NUVOTON_CIPHER */


#if defined(WOLFSSL_NUVOTON_ECC) || defined(WOLFSSL_NUVOTON_RSA)

/* The BSP public key drivers block on a flag that only the CRPT interrupt
 * sets, so the application has to route that interrupt to ECC_DriverISR().
 * The wait loops carry their own timeout and give up rather than hang, but
 * without the handler every public key operation times out. The port reports
 * that as an error rather than declining to software, because a missing
 * handler is a wiring mistake and a silent slow fallback would hide it.
 * the wolfssl-examples project installs the handler; the port README says so too. */

#endif /* WOLFSSL_NUVOTON_ECC || WOLFSSL_NUVOTON_RSA */

#ifdef WOLFSSL_NUVOTON_ECC

/* Map the port's curve selector onto the BSP E_ECC_CURVE value. */
static int nuvoton_ecc_curve(int curveId, E_ECC_CURVE* curve)
{
    switch (curveId) {
        case WC_NUVOTON_CURVE_P192:
            *curve = CURVE_P_192;
            break;
        case WC_NUVOTON_CURVE_P224:
            *curve = CURVE_P_224;
            break;
        case WC_NUVOTON_CURVE_P256:
            *curve = CURVE_P_256;
            break;
        case WC_NUVOTON_CURVE_P384:
            *curve = CURVE_P_384;
            break;
        case WC_NUVOTON_CURVE_P521:
            *curve = CURVE_P_521;
            break;
        case WC_NUVOTON_CURVE_BP256:
            *curve = CURVE_BP_256;
            break;
        case WC_NUVOTON_CURVE_BP384:
            *curve = CURVE_BP_384;
            break;
        case WC_NUVOTON_CURVE_BP512:
            *curve = CURVE_BP_512;
            break;
        default:
            return BAD_FUNC_ARG;
    }

    return 0;
}

int wc_nuvoton_hw_ecc_sign(wc_NuvotonEccReq* req)
{
    int         ret;
    int32_t     rc;
    E_ECC_CURVE curve;

    if (req == NULL || req->msg == NULL || req->r == NULL ||
        req->s == NULL) {
        return BAD_FUNC_ARG;
    }
    if (req->d == NULL || req->k == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = nuvoton_ecc_curve(req->curveId, &curve);
    if (ret != 0) {
        return ret;
    }

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }

    rc = ECC_GenerateSignature(CRPT, curve, req->msg, req->d, req->k,
        req->r, req->s);

    wolfSSL_CryptHwMutexUnLock();

    if (rc != 0) {
        WOLFSSL_MSG("Nuvoton: ECC sign failed");
        return WC_HW_E;
    }

    return 0;
}

int wc_nuvoton_hw_ecc_verify(wc_NuvotonEccReq* req)
{
    int         ret;
    int32_t     rc;
    E_ECC_CURVE curve;

    if (req == NULL || req->msg == NULL || req->qx == NULL ||
        req->qy == NULL || req->r == NULL || req->s == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = nuvoton_ecc_curve(req->curveId, &curve);
    if (ret != 0) {
        return ret;
    }

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }

    rc = ECC_VerifySignature(CRPT, curve, req->msg, req->qx, req->qy, req->r,
        req->s);

    wolfSSL_CryptHwMutexUnLock();

    /* The driver folds "the signature does not check out" and "the engine
     * failed" into the same negative return, so the caller cannot tell them
     * apart and neither can this. Report it as a failed verify, which is the
     * safe reading of the two. */
    if (rc != 0) {
        return SIG_VERIFY_E;
    }

    return 0;
}

int wc_nuvoton_hw_ecc_shared(wc_NuvotonEccReq* req)
{
    int         ret;
    int32_t     rc;
    E_ECC_CURVE curve;

    if (req == NULL || req->qx == NULL || req->qy == NULL ||
        req->out == NULL || req->d == NULL) {
        return BAD_FUNC_ARG;
    }
    if (req->keySlot != WC_NUVOTON_NO_SLOT) {
        /* ECC_GenerateSecretZ_KS() leaves the shared secret in a Key Store
         * slot and hands nothing back, so there is no way to satisfy a caller
         * that asked for the bytes. */
        return BAD_FUNC_ARG;
    }

    ret = nuvoton_ecc_curve(req->curveId, &curve);
    if (ret != 0) {
        return ret;
    }

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }

    rc = ECC_GenerateSecretZ(CRPT, curve, req->d, req->qx, req->qy, req->out);

    wolfSSL_CryptHwMutexUnLock();

    if (rc != 0) {
        WOLFSSL_MSG("Nuvoton: ECDH failed");
        return WC_HW_E;
    }

    return 0;
}

int wc_nuvoton_hw_ecc_pubkey(wc_NuvotonEccReq* req)
{
    int         ret;
    int32_t     rc;
    E_ECC_CURVE curve;

    if (req == NULL || req->qx == NULL || req->qy == NULL) {
        return BAD_FUNC_ARG;
    }
    if (req->keySlot == WC_NUVOTON_NO_SLOT && req->d == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = nuvoton_ecc_curve(req->curveId, &curve);
    if (ret != 0) {
        return ret;
    }

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }

    if (req->keySlot == WC_NUVOTON_NO_SLOT) {
        rc = ECC_GeneratePublicKey(CRPT, curve, req->d, req->qx, req->qy);
    }
    else {
        KS_MEM_Type mem;

        ret = nuvoton_ks_mem(req->keyMem, &mem);
        if (ret != 0) {
            wolfSSL_CryptHwMutexUnLock();
            return ret;
        }
        rc = ECC_GeneratePublicKey_KS(CRPT, curve, mem,
            req->keySlot, req->qx, req->qy, 0);
    }

    wolfSSL_CryptHwMutexUnLock();

    if (rc != 0) {
        WOLFSSL_MSG("Nuvoton: ECC public key failed");
        return WC_HW_E;
    }

    return 0;
}

#endif /* WOLFSSL_NUVOTON_ECC */

#ifdef WOLFSSL_NUVOTON_RSA

/* Map a modulus size in bits onto the BSP RSA_KEY_SIZE_* value. */
static int nuvoton_rsa_keysize(int keyBits, uint32_t* keySize)
{
    switch (keyBits) {
        case 1024:
            *keySize = RSA_KEY_SIZE_1024;
            break;
        case 2048:
            *keySize = RSA_KEY_SIZE_2048;
            break;
        case 3072:
            *keySize = RSA_KEY_SIZE_3072;
            break;
        case 4096:
            *keySize = RSA_KEY_SIZE_4096;
            break;
        default:
            return BAD_FUNC_ARG;
    }

    return 0;
}

int wc_nuvoton_hw_rsa(wc_NuvotonRsaReq* req)
{
    int             ret;
    int32_t         rc;
    uint32_t        keySize = 0;
    uint32_t        opMode;
    word32          timeout;
    RSA_BUF_NORMAL_T* buf;

    if (req == NULL || req->in == NULL || req->n == NULL || req->e == NULL ||
        req->out == NULL) {
        return BAD_FUNC_ARG;
    }
    if (req->keySlot != WC_NUVOTON_NO_SLOT) {
        /* The Key Store form of RSA wants every CRT factor in its own slot,
         * which nuvoton_key.c does not provision yet. */
        return BAD_FUNC_ARG;
    }

    ret = nuvoton_rsa_keysize(req->keyBits, &keySize);
    if (ret != 0) {
        return ret;
    }

    /* The engine works out of a caller supplied scratch area: two kilobytes
     * for the plain mode, and more for CRT. Too big for the stack on a part
     * with this much SRAM, so it comes off the heap for the one call. */
    buf = (RSA_BUF_NORMAL_T*)XMALLOC(sizeof(RSA_BUF_NORMAL_T), NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (buf == NULL) {
        return MEMORY_E;
    }

    /* Zero it. RSA_SetKey() and RSA_SetDMATransfer() load the operands with
     * Hex2Reg(), which writes only as many words as the hex string covers and
     * leaves the rest of each field untouched - unlike the ECC paths, which
     * clean_reg() first. So the high words of the modulus, the exponent and
     * the base are whatever was in this allocation beforehand, and the engine
     * computes against them. The symptom is not an error: the operation
     * completes and returns a wrong result, which surfaces much later as
     * RSA_BUFFER_E out of the OAEP unpad. */
    XMEMSET(buf, 0, sizeof(RSA_BUF_NORMAL_T));

    /* Only the plain modular exponentiation is wired up. CRT needs p, q and
     * the four precomputed values in the CRT working buffer, and a private
     * operation is correct either way, just slower. */
    opMode = RSA_MODE_NORMAL;

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }

    rc = RSA_Open(CRPT, opMode, keySize, buf, sizeof(RSA_BUF_NORMAL_T), 0);
    if (rc == 0) {
        rc = RSA_SetKey(CRPT, req->e);
    }
    if (rc == 0) {
        rc = RSA_SetDMATransfer(CRPT, req->in, req->n, NULL, NULL);
    }
    if (rc == 0) {
        CRPT->INTSTS = CRPT_INTSTS_RSAIF_Msk | CRPT_INTSTS_RSAEIF_Msk;
        RSA_Start(CRPT);

        timeout = WOLFSSL_NUVOTON_HW_TIMEOUT;
        while ((CRPT->INTSTS &
                (CRPT_INTSTS_RSAIF_Msk | CRPT_INTSTS_RSAEIF_Msk)) == 0) {
            if (timeout-- == 0) {
                WOLFSSL_MSG("Nuvoton: RSA timeout");
                rc = -1;
                break;
            }
        }

        if (rc == 0 && (CRPT->INTSTS & CRPT_INTSTS_RSAEIF_Msk) != 0) {
            WOLFSSL_MSG("Nuvoton: RSA error interrupt");
            rc = -1;
        }

        CRPT->INTSTS = CRPT_INTSTS_RSAIF_Msk | CRPT_INTSTS_RSAEIF_Msk;
    }
    if (rc == 0) {
        rc = RSA_Read(CRPT, req->out);
    }

    wolfSSL_CryptHwMutexUnLock();

    ForceZero(buf, sizeof(RSA_BUF_NORMAL_T));
    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (rc != 0) {
        WOLFSSL_MSG("Nuvoton: RSA failed");
        return WC_HW_E;
    }

    return 0;
}

#endif /* WOLFSSL_NUVOTON_RSA */


#ifdef WOLFSSL_NUVOTON_KS

/* The store records the key size as an index, not a bit count. */
static int nuvoton_ks_size_meta(word32 bits, uint32_t* meta)
{
    switch (bits) {
        case 128:  *meta = KS_META_128;  break;
        case 163:  *meta = KS_META_163;  break;
        case 192:  *meta = KS_META_192;  break;
        case 224:  *meta = KS_META_224;  break;
        case 233:  *meta = KS_META_233;  break;
        case 255:  *meta = KS_META_255;  break;
        case 256:  *meta = KS_META_256;  break;
        case 283:  *meta = KS_META_283;  break;
        case 384:  *meta = KS_META_384;  break;
        case 409:  *meta = KS_META_409;  break;
        case 512:  *meta = KS_META_512;  break;
        case 521:  *meta = KS_META_521;  break;
        case 571:  *meta = KS_META_571;  break;
        case 1024: *meta = KS_META_1024; break;
        case 1536: *meta = KS_META_1536; break;
        case 2048: *meta = KS_META_2048; break;
        case 3072: *meta = KS_META_3072; break;
        case 4096: *meta = KS_META_4096; break;
        default:
            return BAD_FUNC_ARG;
    }

    return 0;
}

/* Which engine is allowed to use the key. The store refuses any other. */
static int nuvoton_ks_owner_meta(int owner, uint32_t* meta)
{
    switch (owner) {
        case 0: *meta = KS_META_AES;     break;
        case 1: *meta = KS_META_HMAC;    break;
        case 2: *meta = KS_META_RSA_EXP; break;
        case 3: *meta = KS_META_RSA_MID; break;
        case 4: *meta = KS_META_ECC;     break;
        case 5: *meta = KS_META_CPU;     break;
        default:
            return BAD_FUNC_ARG;
    }

    return 0;
}

int wc_nuvoton_hw_ks_write(wc_NuvotonKsWriteReq* req)
{
    int         ret;
    int32_t     slot;
    KS_MEM_Type mem;
    uint32_t    meta;
    uint32_t    sizeMeta = 0;
    uint32_t    ownerMeta = 0;
    /* The largest key the store holds is 4096 bits. */
    uint32_t    words[4096 / 32];

    if (req == NULL || req->key == NULL || req->keySz == 0 ||
        req->keySz > sizeof(words)) {
        return BAD_FUNC_ARG;
    }

    ret = nuvoton_ks_mem(req->keyMem, &mem);
    if (ret != 0) {
        return ret;
    }
    ret = nuvoton_ks_size_meta(req->bits, &sizeMeta);
    if (ret != 0) {
        return ret;
    }
    ret = nuvoton_ks_owner_meta(req->owner, &ownerMeta);
    if (ret != 0) {
        return ret;
    }

    /* Everything the port writes is a secure key. READABLE is the caller's
     * choice and is what separates a key software can get back from one that
     * only ever leaves the store into an engine. */
    meta = sizeMeta | ownerMeta | KS_META_SECURE;
    if (req->readable) {
        meta |= KS_META_READABLE;
    }

    XMEMSET(words, 0, sizeof(words));
    XMEMCPY(words, req->key, req->keySz);

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        ForceZero(words, sizeof(words));
        return ret;
    }

    slot = KS_Write(mem, meta, words);

    wolfSSL_CryptHwMutexUnLock();

    ForceZero(words, sizeof(words));

    if (slot < 0) {
        WOLFSSL_MSG("Nuvoton: KS_Write failed");
        return WC_HW_E;
    }

    return (int)slot;
}

int wc_nuvoton_hw_ks_read(int keyMem, int keySlot, byte* out, word32 outSz)
{
    int         ret;
    KS_MEM_Type mem;
    uint32_t    words[4096 / 32];

    if (out == NULL || outSz == 0 || outSz > sizeof(words)) {
        return BAD_FUNC_ARG;
    }

    ret = nuvoton_ks_mem(keyMem, &mem);
    if (ret != 0) {
        return ret;
    }

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }

    if (KS_Read(mem, (int32_t)keySlot, words, (outSz + 3) / 4) != 0) {
        WOLFSSL_MSG("Nuvoton: KS_Read failed");
        ret = WC_HW_E;
    }
    else {
        XMEMCPY(out, words, outSz);
    }

    wolfSSL_CryptHwMutexUnLock();

    ForceZero(words, sizeof(words));

    return ret;
}

int wc_nuvoton_hw_ks_erase(int keyMem, int keySlot)
{
    int         ret;
    KS_MEM_Type mem;

    ret = nuvoton_ks_mem(keyMem, &mem);
    if (ret != 0) {
        return ret;
    }

    /* KS_EraseKey() writes KS_SRAM into the metadata itself, so it can only
     * clear a volatile slot. A Flash or OTP key is retired with
     * wc_nuvoton_hw_ks_revoke() instead; there is no per key erase for
     * those. */
    if (mem != KS_SRAM) {
        return BAD_FUNC_ARG;
    }

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }

    if (KS_EraseKey((int32_t)keySlot) != 0) {
        WOLFSSL_MSG("Nuvoton: KS_EraseKey failed");
        ret = WC_HW_E;
    }

    wolfSSL_CryptHwMutexUnLock();

    return ret;
}

int wc_nuvoton_hw_ks_revoke(int keyMem, int keySlot)
{
    int         ret;
    KS_MEM_Type mem;

    ret = nuvoton_ks_mem(keyMem, &mem);
    if (ret != 0) {
        return ret;
    }

    ret = wolfSSL_CryptHwMutexLock();
    if (ret != 0) {
        return ret;
    }

    if (KS_RevokeKey(mem, (int32_t)keySlot) != 0) {
        WOLFSSL_MSG("Nuvoton: KS_RevokeKey failed");
        ret = WC_HW_E;
    }

    wolfSSL_CryptHwMutexUnLock();

    return ret;
}

#endif /* WOLFSSL_NUVOTON_KS */

#endif /* WOLFSSL_NUVOTON_M2354 && WOLFSSL_NUVOTON_SECURE */
