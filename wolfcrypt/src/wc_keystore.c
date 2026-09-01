/* wc_keystore.c
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

#if defined(WOLF_CRYPTO_CB_KEYSTORE) && defined(WOLF_CRYPTO_CB)

#include <wolfssl/wolfcrypt/wc_keystore.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

/* Thin public wrappers over the crypto-callback dispatch, mirroring how
 * wc_she.c sits over the WC_ALGO_TYPE_SHE dispatch. */

int wc_KeyStore_ImportPlain(int devId,
    const byte* keyRef, word32 keyRefSz,
    word32 keyType, const byte* key, word32 keySz,
    word32 attrs, const void* ctx)
{
    return wc_CryptoCb_KeyStoreImportPlain(devId, keyRef, keyRefSz,
        keyType, key, keySz, attrs, ctx);
}

int wc_KeyStore_ExportPlain(int devId,
    const byte* keyRef, word32 keyRefSz,
    byte* key, word32* keySz, const void* ctx)
{
    return wc_CryptoCb_KeyStoreExportPlain(devId, keyRef, keyRefSz,
        key, keySz, ctx);
}

int wc_KeyStore_ImportWrapped(int devId,
    const byte* keyRef, word32 keyRefSz, word32 keyType,
    const byte* wrapKeyRef, word32 wrapKeyRefSz,
    word32 format, const byte* blob, word32 blobSz,
    word32 attrs, const void* ctx)
{
    return wc_CryptoCb_KeyStoreImportWrapped(devId, keyRef, keyRefSz, keyType,
        wrapKeyRef, wrapKeyRefSz, format, blob, blobSz, attrs, ctx);
}

int wc_KeyStore_ExportWrapped(int devId,
    const byte* keyRef, word32 keyRefSz,
    const byte* wrapKeyRef, word32 wrapKeyRefSz,
    word32 format, byte* blob, word32* blobSz, const void* ctx)
{
    return wc_CryptoCb_KeyStoreExportWrapped(devId, keyRef, keyRefSz,
        wrapKeyRef, wrapKeyRefSz, format, blob, blobSz, ctx);
}

int wc_KeyStore_Derive(int devId,
    const byte* keyRef, word32 keyRefSz, word32 keyType,
    const byte* srcKeyRef, word32 srcKeyRefSz,
    word32 kdfType, const byte* deriv, word32 derivSz,
    word32 attrs, const void* ctx)
{
    return wc_CryptoCb_KeyStoreDerive(devId, keyRef, keyRefSz, keyType,
        srcKeyRef, srcKeyRefSz, kdfType, deriv, derivSz, attrs, ctx);
}

int wc_KeyStore_Delete(int devId, const byte* keyRef, word32 keyRefSz,
                       const void* ctx)
{
    return wc_CryptoCb_KeyStoreDelete(devId, keyRef, keyRefSz, ctx);
}

int wc_KeyStore_GetInfo(int devId, const byte* keyRef, word32 keyRefSz,
    word32* keyType, word32* keySz, word32* attrs, const void* ctx)
{
    return wc_CryptoCb_KeyStoreGetInfo(devId, keyRef, keyRefSz,
        keyType, keySz, attrs, ctx);
}

#endif /* WOLF_CRYPTO_CB_KEYSTORE && WOLF_CRYPTO_CB */
