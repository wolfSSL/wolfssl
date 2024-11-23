/* cmac.h
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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


#ifndef WOLF_CRYPT_CMAC_H
#define WOLF_CRYPT_CMAC_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef WOLFSSL_CMAC

#ifndef NO_AES
#include <wolfssl/wolfcrypt/aes.h>
#endif

#if defined(HAVE_FIPS) && \
    defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 2)
    #include <wolfssl/wolfcrypt/fips.h>
#endif /* HAVE_FIPS_VERSION >= 2 */

#ifdef __cplusplus
    extern "C" {
#endif

/* avoid redefinition of structs */
#if !defined(HAVE_FIPS) || FIPS_VERSION3_GE(2,0,0)

typedef enum CmacType {
    WC_CMAC_AES = 1
} CmacType;

#ifndef WC_CMAC_TYPE_DEFINED
    typedef struct Cmac Cmac;
    #define WC_CMAC_TYPE_DEFINED
#endif
struct Cmac {
#ifndef NO_AES
    Aes aes;
    byte buffer[WC_AES_BLOCK_SIZE]; /* partially stored block */
    byte digest[WC_AES_BLOCK_SIZE]; /* running digest */
    byte k1[WC_AES_BLOCK_SIZE];
    byte k2[WC_AES_BLOCK_SIZE];
#endif
    word32 bufferSz;
    word32 totalSz;
#ifdef WOLF_CRYPTO_CB
    int devId;
    void* devCtx;
    #ifdef WOLFSSL_CAAM
    byte ctx[32]; /* hold state for save and return */
    word32 blackKey;
    word32 keylen;
    byte   initialized;
    #endif
#endif
#if defined(WOLFSSL_HASH_KEEP)
    byte*  msg;
    word32 used;
    word32 len;
#endif
#ifdef WOLFSSL_SE050
    byte   useSWCrypt; /* Use SW crypt instead of SE050, before SCP03 auth */
#endif
    CmacType type;
};




#ifndef NO_AES
#define WC_CMAC_TAG_MAX_SZ WC_AES_BLOCK_SIZE
#define WC_CMAC_TAG_MIN_SZ (WC_AES_BLOCK_SIZE/4)
#else
/* Reasonable defaults */
#define WC_CMAC_TAG_MAX_SZ 16
#define WC_CMAC_TAG_MIN_SZ 4
#endif

#if FIPS_VERSION3_GE(6,0,0)
    extern const unsigned int wolfCrypt_FIPS_cmac_ro_sanity[2];
    WOLFSSL_LOCAL int wolfCrypt_FIPS_CMAC_sanity(void);
#endif

#endif /* HAVE_FIPS */

WOLFSSL_API
int wc_InitCmac(Cmac* cmac,
                const byte* key, word32 keySz,
                int type, void* unused);

WOLFSSL_API
int wc_InitCmac_ex(Cmac* cmac,
                const byte* key, word32 keySz,
                int type, void* unused, void* heap, int devId);

WOLFSSL_API
int wc_CmacUpdate(Cmac* cmac,
                  const byte* in, word32 inSz);
WOLFSSL_API
int wc_CmacFinalNoFree(Cmac* cmac,
                       byte* out, word32* outSz);
WOLFSSL_API
int wc_CmacFinal(Cmac* cmac,
                 byte* out, word32* outSz);

WOLFSSL_API
int wc_CmacFree(Cmac* cmac);

#ifndef NO_AES
WOLFSSL_API
int wc_AesCmacGenerate(byte* out, word32* outSz,
                       const byte* in, word32 inSz,
                       const byte* key, word32 keySz);
WOLFSSL_API
int wc_AesCmacGenerate_ex(Cmac *cmac,
                          byte* out, word32* outSz,
                          const byte* in, word32 inSz,
                          const byte* key, word32 keySz,
                          void* heap,
                          int devId);

WOLFSSL_API
int wc_AesCmacVerify(const byte* check, word32 checkSz,
                     const byte* in, word32 inSz,
                     const byte* key, word32 keySz);
WOLFSSL_API
int wc_AesCmacVerify_ex(Cmac* cmac,
                        const byte* check, word32 checkSz,
                        const byte* in, word32 inSz,
                        const byte* key, word32 keySz,
                        void* heap,
                        int devId);
WOLFSSL_LOCAL
void ShiftAndXorRb(byte* out, byte* in);

#endif /* !NO_AES */

#ifdef WOLFSSL_HASH_KEEP
WOLFSSL_API
int wc_CMAC_Grow(Cmac* cmac, const byte* in, int inSz);
#endif

#ifdef __cplusplus
    } /* extern "C" */
#endif


#endif /* WOLFSSL_CMAC */
#endif /* WOLF_CRYPT_CMAC_H */

