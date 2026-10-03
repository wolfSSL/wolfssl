/* nuvoton_key.h
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

/* Key Store keys on the Nuvoton NuMicro M2354.
 *
 * A key written to the store gets a slot; the application then uses the handle
 * rather than the key. Attach an AES key with wc_NuvotonKs_SetAesKey() and the
 * callback runs the operation through the AES_SetKey_KS driver entry point, so
 * the key material never enters wolfCrypt memory. The handle rides in the
 * object's devCtx.
 *
 * AES is the only owner that can be attached. The engine's ECC Key Store path
 * returns signatures that do not verify, so it is not offered; see the port
 * README. */

#ifndef WOLF_CRYPT_NUVOTON_KEY_H
#define WOLF_CRYPT_NUVOTON_KEY_H

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_NUVOTON_M2354) && defined(WOLFSSL_NUVOTON_KS)

#include <wolfssl/wolfcrypt/types.h>
#ifndef NO_AES
    #include <wolfssl/wolfcrypt/aes.h>
#endif
#ifdef HAVE_ECC
    #include <wolfssl/wolfcrypt/ecc.h>
#endif

#ifdef __cplusplus
    extern "C" {
#endif

/* Named here rather than exposing the BSP KS_MEM_Type. */
typedef enum {
    WC_NUVOTON_KS_MEM_SRAM  = 0, /* volatile, cleared by a reset */
    WC_NUVOTON_KS_MEM_FLASH = 1, /* non-volatile */
    WC_NUVOTON_KS_MEM_OTP   = 2  /* one time programmable */
} wc_NuvotonKsMemType;

/* The store enforces this: an AES key cannot be fed to the ECC engine. */
typedef enum {
    WC_NUVOTON_KS_OWNER_AES     = 0,
    WC_NUVOTON_KS_OWNER_HMAC    = 1,
    WC_NUVOTON_KS_OWNER_RSA_EXP = 2,
    WC_NUVOTON_KS_OWNER_RSA_MID = 3,
    WC_NUVOTON_KS_OWNER_ECC     = 4,
    WC_NUVOTON_KS_OWNER_CPU     = 5
} wc_NuvotonKsOwner;

/* Held in the devCtx of the Aes or ecc_key it belongs to. */
typedef struct wc_NuvotonKsKey {
    int    slot;    /* index the store gave it */
    int    mem;     /* wc_NuvotonKsMemType */
    int    owner;   /* wc_NuvotonKsOwner */
    word32 bits;    /* key size in bits */
} wc_NuvotonKsKey;

/* Write key material and fill in ksKey with the handle. bits must be a size
 * the store holds (128, 192, 224, 233, 255, 256, 283, 384, 409, 512, 521, 571,
 * 1024, 1536, 2048, 3072, 4096). readable allows wc_NuvotonKs_Read() later;
 * leave it 0 for a key that should never come out. OTP is permanent. */
WOLFSSL_API int wc_NuvotonKs_Write(wc_NuvotonKsKey* ksKey, int mem, int owner,
    word32 bits, const byte* key, word32 keySz, int readable);

/* Only works for a slot written with readable set. */
WOLFSSL_API int wc_NuvotonKs_Read(const wc_NuvotonKsKey* ksKey, byte* out,
    word32 outSz);

/* Clear a volatile slot. Flash and OTP have no per key erase; revoke. */
WOLFSSL_API int wc_NuvotonKs_Erase(const wc_NuvotonKsKey* ksKey);

/* Retire a key permanently. Cannot be undone. */
WOLFSSL_API int wc_NuvotonKs_Revoke(const wc_NuvotonKsKey* ksKey);

#ifndef NO_AES
/* The Aes must carry the port's devId, and ksKey must outlive it. */
WOLFSSL_API int wc_NuvotonKs_SetAesKey(Aes* aes, wc_NuvotonKsKey* ksKey);
#endif

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* WOLFSSL_NUVOTON_M2354 && WOLFSSL_NUVOTON_KS */

#endif /* WOLF_CRYPT_NUVOTON_KEY_H */
