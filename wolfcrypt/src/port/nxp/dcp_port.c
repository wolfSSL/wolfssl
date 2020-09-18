/* dcp_port.c
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif
    
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifdef WOLFSSL_IMXRT_DCP

#ifndef DCP_USE_OTP_KEY
#define DCP_USE_OTP_KEY 0 /* Set to 1 to select OTP key for AES encryption/decryption. */
#endif

#include "fsl_device_registers.h"
#include "fsl_debug_console.h"
#include "fsl_dcp.h"


static dcp_config_t dcpConfig;

#if DCP_USE_OTP_KEY
typedef enum _dcp_otp_key_select
{
    kDCP_OTPMKKeyLow  = 1U, /* Use [127:0] from snvs key as dcp key */
    kDCP_OTPMKKeyHigh = 2U, /* Use [255:128] from snvs key as dcp key */
    kDCP_OCOTPKeyLow  = 3U, /* Use [127:0] from ocotp key as dcp key */
    kDCP_OCOTPKeyHigh = 4U  /* Use [255:128] from ocotp key as dcp key */
} dcp_otp_key_select;
#endif

#if DCP_USE_OTP_KEY
static status_t DCP_OTPKeySelect(dcp_otp_key_select keySelect)
{
    if (keySelect == kDCP_OTPMKKeyLow)
    {
        IOMUXC_GPR->GPR3 &= ~(1 << IOMUXC_GPR_GPR3_DCP_KEY_SEL_SHIFT);
        IOMUXC_GPR->GPR10 &= ~(1 << IOMUXC_GPR_GPR10_DCPKEY_OCOTP_OR_KEYMUX_SHIFT);
    }

    else if (keySelect == kDCP_OTPMKKeyHigh)
    {
        IOMUXC_GPR->GPR3 |= (1 << IOMUXC_GPR_GPR3_DCP_KEY_SEL_SHIFT);
        IOMUXC_GPR->GPR10 &= ~(1 << IOMUXC_GPR_GPR10_DCPKEY_OCOTP_OR_KEYMUX_SHIFT);
    }

    else if (keySelect == kDCP_OCOTPKeyLow)
    {
        IOMUXC_GPR->GPR3 &= ~(1 << IOMUXC_GPR_GPR3_DCP_KEY_SEL_SHIFT);
        IOMUXC_GPR->GPR10 |= (1 << IOMUXC_GPR_GPR10_DCPKEY_OCOTP_OR_KEYMUX_SHIFT);
    }

    else if (keySelect == kDCP_OCOTPKeyHigh)
    {
        IOMUXC_GPR->GPR3 |= (1 << IOMUXC_GPR_GPR3_DCP_KEY_SEL_SHIFT);
        IOMUXC_GPR->GPR10 |= (1 << IOMUXC_GPR_GPR10_DCPKEY_OCOTP_OR_KEYMUX_SHIFT);
    }

    else
    {
        return kStatus_InvalidArgument;
    }

    return kStatus_Success;
}
#endif

static void dcp_init(void)
{
    static int dcp_is_initialized = 0;
    if (!dcp_is_initialized) {
        /* Initialize DCP */
        DCP_GetDefaultConfig(&dcpConfig);

#if DCP_USE_OTP_KEY
        /* Set OTP key type in IOMUX registers before initializing DCP. */
        /* Software reset of DCP must be issued after changing the OTP key type. */
        DCP_OTPKeySelect(kDCP_OTPMKKeyLow);
#endif

        /* Reset and initialize DCP */
        DCP_Init(DCP, &dcpConfig);
        dcp_is_initialized++;
    }
}


#ifndef NO_AES
int  DCPAesSetKey(Aes* aes, const byte* key, word32 len, const byte* iv,
                          int dir)
{

#if DCP_USE_OTP_KEY
#warning Please update cipherAes128 variables to match expected AES ciphertext for your OTP key.
#endif
    status_t status;
    if (!aes || !key)
        return BAD_FUNC_ARG;

    if (len != 16)
        return BAD_FUNC_ARG; 

    dcp_init();
    XMEMSET(&aes->handle, 0, sizeof(aes->handle));
    aes->handle.channel    = kDCP_Channel0;
    aes->handle.swapConfig = kDCP_NoSwap;
#if DCP_USE_OTP_KEY
    aes->handle.keySlot = kDCP_OtpKey;
#else
    aes->handle.keySlot = kDCP_KeySlot0;
#endif
    status = DCP_AES_SetKey(DCP, &aes->handle, key, 16);
    if (status != kStatus_Success)
        return WC_HW_E;
    if (iv)
        XMEMCPY(aes->reg, iv, 16);
    else
        XMEMSET(aes->reg, 0, 16);
    return 0;
}

int  DCPAesCbcEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    int ret;
    if (sz % 16)
        return BAD_FUNC_ARG;
    ret = DCP_AES_EncryptCbc(DCP, &aes->handle, in, out, sz, (const byte *)aes->reg);
    if (ret)
        return WC_HW_E; 
    XMEMCPY(aes->reg, out, AES_BLOCK_SIZE);
    return ret;
}

int  DCPAesCbcDecrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    int ret;
    if (sz % 16)
        return BAD_FUNC_ARG;
    ret = DCP_AES_DecryptCbc(DCP, &aes->handle, in, out, sz, (const byte *)aes->reg);
    if (ret)
        return WC_HW_E; 
    XMEMCPY(aes->reg, in, AES_BLOCK_SIZE);
    return ret;
}

int  DCPAesEcbEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    return DCP_AES_EncryptEcb(DCP, &aes->handle, in, out, sz);
}

int  DCPAesEcbDecrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    return DCP_AES_DecryptEcb(DCP, &aes->handle, in, out, sz);
}

#endif

#ifndef NO_SHA256
int wc_InitSha256_ex(wc_Sha256* sha256, void* heap, int devId)
{
    int ret;
    if (sha256 == NULL)
        return BAD_FUNC_ARG;
    dcp_init();
    (void)devId;
    XMEMSET(sha256, 0, sizeof(wc_Sha256));
    sha256->handle.channel    = kDCP_Channel0;
    sha256->handle.keySlot    = kDCP_KeySlot0;
    sha256->handle.swapConfig = kDCP_NoSwap;
    ret = DCP_HASH_Init(DCP, &sha256->handle, &sha256->ctx, kDCP_Sha256);
    if (ret != kStatus_Success)
        return WC_HW_E;
    return ret;
}

int wc_InitSha256(wc_Sha256* sha256)
{
    return wc_InitSha256_ex(sha256, NULL, INVALID_DEVID);
}

void wc_Sha256Free(wc_Sha256* sha256)
{
    (void)sha256;
}

int wc_Sha256Update(wc_Sha256* sha256, const byte* data, word32 len)
{
    int ret;
    if (sha256 == NULL || (data == NULL && len != 0)) {
        return BAD_FUNC_ARG;
    }
    ret = DCP_HASH_Update(DCP, &sha256->ctx, data, len);
    if (ret != kStatus_Success)
        return WC_HW_E;
    return ret;
}


int wc_Sha256GetHash(wc_Sha256* sha256, byte* hash)
{
    int ret;
    size_t outlen = WC_SHA256_DIGEST_SIZE;
    dcp_hash_ctx_t saved_ctx;
    if (sha256 == NULL || hash == NULL)
        return BAD_FUNC_ARG;
    XMEMCPY(&saved_ctx, &sha256->ctx, sizeof(dcp_hash_ctx_t));
    XMEMSET(hash, 0, WC_SHA256_DIGEST_SIZE);
    ret = DCP_HASH_Finish(DCP, &sha256->ctx, hash, &outlen);
    if ((ret != kStatus_Success) || (outlen != SHA256_DIGEST_SIZE)) {
        return WC_HW_E;
    }
    XMEMCPY(&sha256->ctx, &saved_ctx, sizeof(dcp_hash_ctx_t));
    return 0;
}

int wc_Sha256Final(wc_Sha256* sha256, byte* hash)
{
    int ret;
    size_t outlen = WC_SHA256_DIGEST_SIZE;
    ret = DCP_HASH_Finish(DCP, &sha256->ctx, hash, &outlen);
    if ((ret != kStatus_Success) || (outlen != SHA256_DIGEST_SIZE))
        return WC_HW_E;
    sha256->handle.channel    = kDCP_Channel0;
    sha256->handle.keySlot    = kDCP_KeySlot0;
    sha256->handle.swapConfig = kDCP_NoSwap;
    ret = DCP_HASH_Init(DCP, &sha256->handle, &sha256->ctx, kDCP_Sha256);
    if (ret < 0)
        return WC_HW_E;
    return ret;
}

#if defined(WOLFSSL_HASH_FLAGS) || defined(WOLF_CRYPTO_CB)
int wc_Sha256SetFlags(wc_Sha256* sha256, word32 flags)
{
    if (sha256) {
        sha256->flags = flags;
    }
    return 0;
}
int wc_Sha256GetFlags(wc_Sha256* sha256, word32* flags)
{
    if (sha256 && flags) {
        *flags = sha256->flags;
    }
    return 0;
}
#endif /* WOLFSSL_HASH_FLAGS || WOLF_CRYPTO_CB */

int wc_Sha256Copy(wc_Sha256* src, wc_Sha256* dst)
{
    if (src == NULL || dst == NULL)
        return BAD_FUNC_ARG;
    XMEMCPY(&dst->ctx, &src->ctx, sizeof(dcp_hash_ctx_t));
    return 0;
}
#endif /* !NO_SHA256 */


#ifndef NO_SHA

int wc_InitSha_ex(wc_Sha* sha, void* heap, int devId)
{
    int ret;
    if (sha == NULL)
        return BAD_FUNC_ARG;
    dcp_init();
    (void)devId;
    XMEMSET(sha, 0, sizeof(wc_Sha));
    sha->handle.channel    = kDCP_Channel0;
    sha->handle.keySlot    = kDCP_KeySlot0;
    sha->handle.swapConfig = kDCP_NoSwap;
    ret = DCP_HASH_Init(DCP, &sha->handle, &sha->ctx, kDCP_Sha1);
    if (ret != kStatus_Success)
        return WC_HW_E;
    return ret;
}

int wc_InitSha(wc_Sha* sha)
{
    return wc_InitSha_ex(sha, NULL, INVALID_DEVID);
}

void wc_ShaFree(wc_Sha* sha)
{
    (void)sha;
}

int wc_ShaUpdate(wc_Sha* sha, const byte* data, word32 len)
{
    int ret;
    if (sha == NULL || (data == NULL && len != 0)) {
        return BAD_FUNC_ARG;
    }
    ret = DCP_HASH_Update(DCP, &sha->ctx, data, len);
    if (ret != kStatus_Success)
        return WC_HW_E;
    return ret;
}


int wc_ShaGetHash(wc_Sha* sha, byte* hash)
{
    int ret;
    size_t outlen = WC_SHA_DIGEST_SIZE;
    dcp_hash_ctx_t saved_ctx;
    if (sha == NULL || hash == NULL)
        return BAD_FUNC_ARG;
    XMEMCPY(&saved_ctx, &sha->ctx, sizeof(dcp_hash_ctx_t));
    XMEMSET(hash, 0, WC_SHA_DIGEST_SIZE);
    ret = DCP_HASH_Finish(DCP, &sha->ctx, hash, &outlen);
    if ((ret != kStatus_Success) || (outlen != WC_SHA_DIGEST_SIZE)) {
        return WC_HW_E;
    }
    XMEMCPY(&sha->ctx, &saved_ctx, sizeof(dcp_hash_ctx_t));
    return 0;
}

int wc_ShaFinal(wc_Sha* sha, byte* hash)
{
    int ret;
    size_t outlen = WC_SHA_DIGEST_SIZE;
    ret = DCP_HASH_Finish(DCP, &sha->ctx, hash, &outlen);
    if ((ret != kStatus_Success) || (outlen != SHA_DIGEST_SIZE))
        return WC_HW_E;
    sha->handle.channel    = kDCP_Channel0;
    sha->handle.keySlot    = kDCP_KeySlot0;
    sha->handle.swapConfig = kDCP_NoSwap;
    ret = DCP_HASH_Init(DCP, &sha->handle, &sha->ctx, kDCP_Sha1);
    if (ret < 0)
        return WC_HW_E;
    return ret;
}

#if defined(WOLFSSL_HASH_FLAGS) || defined(WOLF_CRYPTO_CB)
int wc_ShaSetFlags(wc_Sha* sha, word32 flags)
{
    if (sha) {
        sha->flags = flags;
    }
    return 0;
}
int wc_ShaGetFlags(wc_Sha* sha, word32* flags)
{
    if (sha && flags) {
        *flags = sha->flags;
    }
    return 0;
}
#endif /* WOLFSSL_HASH_FLAGS || WOLF_CRYPTO_CB */

int wc_ShaCopy(wc_Sha* src, wc_Sha* dst)
{
    if (src == NULL || dst == NULL)
        return BAD_FUNC_ARG;
    XMEMCPY(&dst->ctx, &src->ctx, sizeof(dcp_hash_ctx_t));
    return 0;
}
#endif /* !NO_SHA */

#endif /* WOLFSSL_IMXRT_DCP */
