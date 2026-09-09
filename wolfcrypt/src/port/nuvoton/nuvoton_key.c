/* nuvoton_key.c
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

/* Key Store keys on the M2354. See wolfssl/wolfcrypt/port/nuvoton/nuvoton_key.h
 * for what the API is for; this is the thin layer between it and the hardware
 * calls, plus the two functions that attach a stored key to a wolfCrypt
 * object. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_NUVOTON_M2354) && defined(WOLFSSL_NUVOTON_KS)

#include <wolfssl/wolfcrypt/port/nuvoton/nuvoton_key.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>

#include "wolfcrypt/src/port/nuvoton/nuvoton_hw.h"

/* ForceZero() when a stored-key handle replaces existing key material. */
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

int wc_NuvotonKs_Write(wc_NuvotonKsKey* ksKey, int mem, int owner,
    word32 bits, const byte* key, word32 keySz, int readable)
{
    wc_NuvotonKsWriteReq req;
    int                  slot;

    if (ksKey == NULL || key == NULL || keySz == 0) {
        return BAD_FUNC_ARG;
    }
    /* The store records the size separately from the material, so a mismatch
     * would silently write a key of the wrong length. */
    if (bits == 0 || ((bits + 7) / 8) != keySz) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(&req, 0, sizeof(req));
    req.key      = key;
    req.keySz    = keySz;
    req.bits     = bits;
    req.keyMem   = mem;
    req.owner    = owner;
    req.readable = readable;

    slot = wc_nuvoton_hw_ks_write(&req);
    if (slot < 0) {
        return slot;
    }

    ksKey->slot  = slot;
    ksKey->mem   = mem;
    ksKey->owner = owner;
    ksKey->bits  = bits;

    return 0;
}

int wc_NuvotonKs_Read(const wc_NuvotonKsKey* ksKey, byte* out, word32 outSz)
{
    if (ksKey == NULL || out == NULL || outSz == 0) {
        return BAD_FUNC_ARG;
    }

    return wc_nuvoton_hw_ks_read(ksKey->mem, ksKey->slot, out, outSz);
}

int wc_NuvotonKs_Erase(const wc_NuvotonKsKey* ksKey)
{
    if (ksKey == NULL) {
        return BAD_FUNC_ARG;
    }

    return wc_nuvoton_hw_ks_erase(ksKey->mem, ksKey->slot);
}

int wc_NuvotonKs_Revoke(const wc_NuvotonKsKey* ksKey)
{
    if (ksKey == NULL) {
        return BAD_FUNC_ARG;
    }

    return wc_nuvoton_hw_ks_revoke(ksKey->mem, ksKey->slot);
}

#ifndef NO_AES
int wc_NuvotonKs_SetAesKey(Aes* aes, wc_NuvotonKsKey* ksKey)
{
    if (aes == NULL || ksKey == NULL) {
        return BAD_FUNC_ARG;
    }
    if (ksKey->owner != WC_NUVOTON_KS_OWNER_AES) {
        return BAD_FUNC_ARG;
    }
    if (ksKey->bits != 128 && ksKey->bits != 192 && ksKey->bits != 256) {
        return BAD_FUNC_ARG;
    }

    /* Any key this Aes already held has to go. Leaving the software schedule
     * and devKey in place means a later decline to software silently encrypts
     * with the previous key instead of failing, and keeps that key in memory
     * for as long as the object lives. */
    ForceZero(aes->key, sizeof(aes->key));
#ifdef WOLFSSL_AES_COUNTER
    aes->left = 0;
#endif
#ifdef WC_AES_KEY_IS_SET
    aes->keyInstalled = 0;
#endif

    /* wc_AesSetKey() is what normally fills keylen in, and it is not called
     * for a stored key because there is no key material to give it. The
     * cipher callback still needs the length to pick the engine key size. */
    aes->keylen = (int)(ksKey->bits / 8);
    aes->rounds = (ksKey->bits / 32) + 6;
    aes->devCtx = ksKey;

    return 0;
}
#endif /* !NO_AES */


#endif /* WOLFSSL_NUVOTON_M2354 && WOLFSSL_NUVOTON_KS */
