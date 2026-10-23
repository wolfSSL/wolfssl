/* els_pkc_port.h
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

#ifndef WOLF_CRYPT_ELS_PKC_PORT_H
#define WOLF_CRYPT_ELS_PKC_PORT_H

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_ELS_PKC

#ifndef WOLF_CRYPTO_CB
    #error "WOLFSSL_ELS_PKC requires WOLF_CRYPTO_CB"
#endif

/* The slot reference travels as a key's id blob, which wc_ecc_init_id() and
 * wc_AesInit_Id() set. NO_WOLF_PRIVATE_KEY_ID removes both. */
#ifndef WOLF_PRIVATE_KEY_ID
    #error "WOLFSSL_ELS_PKC key slot references require WOLF_PRIVATE_KEY_ID"
#endif

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#ifndef NO_AES
    #include <wolfssl/wolfcrypt/aes.h>
#endif
#if defined(WOLFSSL_CMAC) && !defined(NO_AES)
    #include <wolfssl/wolfcrypt/cmac.h>
#endif

#ifdef __cplusplus
    extern "C" {
#endif

/* WOLFSSL_ELS_PKC_DEVID comes from settings.h. */

#ifndef WOLFSSL_ELS_PKC_IRQ_PRIO
    #define WOLFSSL_ELS_PKC_IRQ_PRIO 2
#endif

/* Slot reference, carried as the key's id blob; wolfPSA stores the same 16
 * bytes followed by the public point. Never redefine a field; bump ver.
 *
 *   off  size  field
 *   0    2     magic 'E','L'
 *   2    1     ver
 *   3    1     keyClass
 *   4    1     slot
 *   5    1     flags
 *   6    2     reserved, zero
 *   8    8     bind - first 8 bytes of SHA-256 over the X9.62 public point,
 *              zero for symmetric keys
 */

/* Highest slot index a reference may name, mirroring the vendor header's
 * MCUXCLELS_KEY_SLOTS so a caller need not include the NXP SDK. */
#define WC_ELSPKC_MAX_SLOT       19

#define WC_ELSPKC_KEYREF_SZ      16
#define WC_ELSPKC_KEYREF_MAGIC_0 0x45  /* 'E' */
#define WC_ELSPKC_KEYREF_MAGIC_1 0x4C  /* 'L' */
#define WC_ELSPKC_KEYREF_VER     1
#define WC_ELSPKC_BIND_SZ        8

/* One ELS permission bit per class. RSA and the Ed curves have none, so
 * they run on the PKC with in-memory keys. */
enum wc_ElsPkc_KeyClass {
    WC_ELSPKC_KEY_NONE     = 0,
    WC_ELSPKC_KEY_ECC_SIGN = 1,   /* ELS uecsg */
    WC_ELSPKC_KEY_ECC_DH   = 2,   /* ELS uecdh */
    WC_ELSPKC_KEY_ECC_SEED = 3,   /* ELS ukgsrc */
    WC_ELSPKC_KEY_AES      = 4,   /* ELS uaes  */
    WC_ELSPKC_KEY_HMAC     = 5,   /* ELS uhmac */
    WC_ELSPKC_KEY_CMAC     = 6,   /* ELS ucmac */
    WC_ELSPKC_KEY_KWK      = 7,   /* ELS ukwk / ukuok */
    WC_ELSPKC_KEY_CKDF     = 8,   /* ELS uckdf */
    WC_ELSPKC_KEY_HKDF     = 9,   /* ELS uhkdf */
    WC_ELSPKC_KEY_MAX      = WC_ELSPKC_KEY_HKDF
};

/* bit0 is set when bind[] carries a real value; bits 1-2 are creation-time
 * attributes, meaningful only on a key generation. */
#define WC_ELSPKC_REF_FLAG_BIND       0x01
#define WC_ELSPKC_REF_FLAG_EXPORTABLE 0x02  /* ELS wrpok */
#define WC_ELSPKC_REF_FLAG_PERSISTENT 0x04  /* ELS frtn  */

typedef struct wc_ElsPkc_KeyRef {
    byte keyClass;
    byte slot;
    byte flags;
    byte bind[WC_ELSPKC_BIND_SZ];
} wc_ElsPkc_KeyRef;

/* out == NULL is a size query returning LENGTH_ONLY_E. Parse returns
 * BAD_STATE_E for a bad blob and touches no hardware. */
WOLFSSL_API int wc_ElsPkc_MakeKeyRef(const wc_ElsPkc_KeyRef* ref, byte* out,
                                     word32* outSz);
WOLFSSL_API int wc_ElsPkc_ParseKeyRef(const byte* in, word32 inSz,
                                      wc_ElsPkc_KeyRef* ref);

#ifndef NO_AES
/* Same for an Aes; keylen stays 0 and the engine takes the size from the
 * slot. Only WC_ELSPKC_KEY_AES drives a cipher. */
WOLFSSL_API int wc_ElsPkc_AesUseSlot(Aes* aes, const wc_ElsPkc_KeyRef* ref,
                                     void* heap, int devId);
#endif

#if defined(WOLFSSL_CMAC) && !defined(NO_AES)
/* Same, for a Cmac. The slot must carry ucmac, which is a separate permission
 * from uaes, so a slot holding both needs one reference per class. */
WOLFSSL_API int wc_ElsPkc_CmacUseSlot(Cmac* cmac, const wc_ElsPkc_KeyRef* ref,
                                      void* heap, int devId);
#endif

/* wolfCrypt_Init() already calls this; call it again only after
 * wolfCrypt_Cleanup(). */
WOLFSSL_API int wc_ElsPkc_Init(void);

/* Unregister the callback and close the port; the mutex is kept for reuse.
 * Finish every context the port holds state for first. */
WOLFSSL_API int wc_ElsPkc_Cleanup(void);

/* The callback, for registering under another devId. A context opts in by
 * being initialised with that devId. */
WOLFSSL_API int wc_ElsPkc_CryptoCb(int devId, wc_CryptoInfo* info, void* ctx);

#ifndef WC_NO_RNG
/* wc_GenerateSeed() where no OS entropy source precedes it in random.c. Fails
 * with BAD_STATE_E until wc_ElsPkc_Init() has run. */
WOLFSSL_LOCAL int wc_ElsPkc_GenerateSeed(byte* output, word32 sz);
#endif

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFSSL_ELS_PKC */
#endif /* WOLF_CRYPT_ELS_PKC_PORT_H */
