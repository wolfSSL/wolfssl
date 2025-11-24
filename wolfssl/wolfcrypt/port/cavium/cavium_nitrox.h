/* cavium_nitrox.h
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifndef _CAVIUM_NITROX_H_
#define _CAVIUM_NITROX_H_

#ifdef HAVE_CAVIUM

#ifndef HAVE_CAVIUM_V
    #include "cavium_sysdep.h"
#endif
#include "cavium_common.h"

#define CAVIUM_SSL_GRP      0
#define CAVIUM_DPORT        256

/* Compatibility with older Cavium SDK's */
#ifndef HAVE_CAVIUM_V
    typedef int    CspHandle;
    typedef word32 CavReqId;

    #define AES_128 AES_128_BIT
    #define AES_192 AES_192_BIT
    #define AES_256 AES_256_BIT

    #define MAX_TO_POLL 30
    typedef int    context_type_t;

    struct CspMultiRequestStatusBuffer {
        int count;
        CspRequestStatusBuffer req[MAX_TO_POLL];
    };
    #define AES_CBC 0x3
    #define AES_GCM 0x7
#else
    typedef word64 CavReqId;
    #define CAVIUM_DEV_ID       0
    #define CAVIUM_BLOCKING     BLOCKING
    #define CAVIUM_NON_BLOCKING NON_BLOCKING
    #define CAVIUM_DIRECT       DMA_DIRECT_DIRECT
#endif

typedef struct CspMultiRequestStatusBuffer CspMultiRequestStatusBuffer;

#ifdef WOLFSSL_ASYNC_CRYPT
    #define CAVIUM_REQ_MODE CAVIUM_NON_BLOCKING
#else
    #define CAVIUM_REQ_MODE CAVIUM_BLOCKING
#endif


#ifdef WOLFSSL_ASYNC_CRYPT
    #ifndef CAVIUM_MAX_PENDING
        #define CAVIUM_MAX_PENDING  10 /* 90 */
    #endif
    #ifndef CAVIUM_MAX_POLL
        #define CAVIUM_MAX_POLL     MAX_TO_POLL
    #endif
#endif


typedef struct CaviumNitroxDev {
    CspHandle      devId;         /* nitrox device id */
    context_type_t type;          /* Typically CONTEXT_SSL, but also ECC types*/
    word64         contextHandle; /* nitrox context memory handle */
    CavReqId       reqId;         /* Current requestId */
} CaviumNitroxDev;

struct WOLF_EVENT;
struct WC_ASYNC_DEV;
struct WC_BIGINT;

/* Wrapper API's */
WOLFSSL_LOCAL int NitroxTranslateResponseCode(int ret);
WOLFSSL_LOCAL CspHandle NitroxGetDeviceHandle(void);
WOLFSSL_LOCAL CspHandle NitroxOpenDeviceDefault(void);
WOLFSSL_LOCAL CspHandle NitroxOpenDevice(int dma_mode, int dev_id);
WOLFSSL_LOCAL int NitroxAllocContext(struct WC_ASYNC_DEV* dev, CspHandle devId,
    context_type_t type);
WOLFSSL_LOCAL void NitroxFreeContext(struct WC_ASYNC_DEV* dev);
WOLFSSL_LOCAL void NitroxCloseDevice(CspHandle devId);

#if defined(WOLFSSL_ASYNC_CRYPT)
WOLFSSL_LOCAL int NitroxCheckRequest(struct WC_ASYNC_DEV* dev,
    struct WOLF_EVENT* event);
WOLFSSL_LOCAL int NitroxCheckRequests(struct WC_ASYNC_DEV* dev,
    CspMultiRequestStatusBuffer* req_stat_buf);
#endif /* WOLFSSL_ASYNC_CRYPT */


/* Crypto wrappers */
#ifndef NO_RSA
    struct RsaKey;
    WOLFSSL_LOCAL int NitroxRsaExptMod(
                            const byte* in, word32 inLen,
                            byte* exponent, word32 expLen,
                            byte* modulus, word32 modLen,
                            byte* out, word32* outLen, struct RsaKey* key);
    WOLFSSL_LOCAL int NitroxRsaPublicEncrypt(const byte* in, word32 inLen,
                                byte* out, word32 outLen, struct RsaKey* key);
    WOLFSSL_LOCAL int NitroxRsaPrivateDecrypt(const byte* in, word32 inLen,
                                byte* out, word32* outLen, struct RsaKey* key);
    WOLFSSL_LOCAL int NitroxRsaSSL_Sign(const byte* in, word32 inLen,
                                byte* out, word32 outLen, struct RsaKey* key);
    WOLFSSL_LOCAL int NitroxRsaSSL_Verify(const byte* in, word32 inLen,
                                byte* out, word32 *outLen, struct RsaKey* key);
#endif /* !NO_RSA */

#if defined(HAVE_ECC) && defined(HAVE_CAVIUM_V)
    struct ecc_key;
    WOLFSSL_LOCAL int NitroxEccGetSize(struct ecc_key* key);
    WOLFSSL_LOCAL int NitroxEccRsSplit(struct ecc_key* key,
        struct WC_BIGINT* r, struct WC_BIGINT* s);
    WOLFSSL_LOCAL int NitroxEccIsCurveSupported(struct ecc_key* key);
    WOLFSSL_LOCAL int NitroxEccPad(struct WC_BIGINT* bi, word32 padTo);
    #ifdef HAVE_ECC_DHE
        WOLFSSL_LOCAL int NitroxEcdh(struct ecc_key* key,
            struct WC_BIGINT* k, struct WC_BIGINT* xG, struct WC_BIGINT* yG,
            byte* out, word32* outlen, struct WC_BIGINT* q);
    #endif /* HAVE_ECC_DHE */
    #ifdef HAVE_ECC_SIGN
        WOLFSSL_LOCAL int NitroxEcdsaSign(struct ecc_key* key,
            struct WC_BIGINT* m, struct WC_BIGINT* d,
            struct WC_BIGINT* k,
            struct WC_BIGINT* r, struct WC_BIGINT* s,
            struct WC_BIGINT* q, struct WC_BIGINT* n);
    #endif /* HAVE_ECC_SIGN */
    #ifdef HAVE_ECC_VERIFY
        WOLFSSL_LOCAL int NitroxEcdsaVerify(struct ecc_key* key,
            struct WC_BIGINT* m, struct WC_BIGINT* xp,
            struct WC_BIGINT* yp, struct WC_BIGINT* r,
            struct WC_BIGINT* s, struct WC_BIGINT* q,
            struct WC_BIGINT* n, int* stat);
    #endif /* HAVE_ECC_VERIFY */
#endif /* HAVE_ECC */

#ifndef NO_AES
    struct Aes;
    #ifdef HAVE_AES_CBC
        WOLFSSL_LOCAL int NitroxAesCbcEncrypt(struct Aes* aes, byte* out,
                                                const byte* in, word32 length);
    #ifdef HAVE_AES_DECRYPT
        WOLFSSL_LOCAL int NitroxAesCbcDecrypt(struct Aes* aes, byte* out,
                                                const byte* in, word32 length);
    #endif /* HAVE_AES_DECRYPT */
    #endif /* HAVE_AES_CBC */

    #ifdef HAVE_AESGCM
        WOLFSSL_LOCAL int NitroxAesGcmEncrypt(struct Aes* aes,
            byte* out, const byte* in, word32 sz,
            const byte* key, word32 keySz,
            const byte* iv, word32 ivSz,
            byte* authTag, word32 authTagSz,
            const byte* authIn, word32 authInSz);
    #ifdef HAVE_AES_DECRYPT
        WOLFSSL_LOCAL int NitroxAesGcmDecrypt(struct Aes* aes,
            byte* out, const byte* in, word32 sz,
            const byte* key, word32 keySz,
            const byte* iv, word32 ivSz,
            const byte* authTag, word32 authTagSz,
            const byte* authIn, word32 authInSz);
    #endif /* HAVE_AES_DECRYPT */
    #endif /* HAVE_AESGCM */
#endif /* !NO_AES */

#ifndef NO_RC4
    struct Arc4;
    WOLFSSL_LOCAL int NitroxArc4SetKey(struct Arc4* arc4, const byte* key,
                                                                word32 length);
    WOLFSSL_LOCAL int NitroxArc4Process(struct Arc4* arc4, byte* out,
                                                const byte* in, word32 length);
#endif /* !NO_RC4 */

#ifndef NO_DES3
    struct Des3;
    WOLFSSL_LOCAL int NitroxDes3SetKey(struct Des3* des3, const byte* key,
                                                               const byte* iv);
    WOLFSSL_LOCAL int NitroxDes3CbcEncrypt(struct Des3* des3, byte* out,
                                                const byte* in, word32 length);
    WOLFSSL_LOCAL int NitroxDes3CbcDecrypt(struct Des3* des3, byte* out,
                                                const byte* in, word32 length);
#endif /* !NO_DES3 */

#ifndef NO_HMAC
    struct Hmac;
    WOLFSSL_LOCAL int NitroxHmacUpdate(struct Hmac* hmac, const byte* msg,
                                                                word32 length);
    WOLFSSL_LOCAL int NitroxHmacFinal(struct Hmac* hmac, byte* hash,
                                                                word16 hashLen);
#endif /* NO_HMAC */

struct WC_RNG;
WOLFSSL_API int NitroxRngGenerateBlock(struct WC_RNG* rng, byte* output,
    word32 sz);


#endif /* HAVE_CAVIUM */

#endif /* _CAVIUM_NITROX_H_ */
