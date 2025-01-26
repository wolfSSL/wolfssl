/* cmac.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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
#ifdef WOLFSSL_QNX_CAAM
#include <wolfssl/wolfcrypt/port/caam/wolfcaam.h>
#endif
#if defined(WOLFSSL_HASH_KEEP)
#include <wolfssl/wolfcrypt/hash.h>
#endif

#if defined(WOLFSSL_CMAC)

#if defined(HAVE_FIPS) && defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 2)
    /* set NO_WRAPPERS before headers, use direct internal f()s not wrappers */
    #define FIPS_NO_WRAPPERS

    #ifdef USE_WINDOWS_API
        #pragma code_seg(".fipsA$c")
        #pragma const_seg(".fipsB$c")
    #endif
#endif

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/cmac.h>

#ifdef WOLF_CRYPTO_CB
    #include <wolfssl/wolfcrypt/cryptocb.h>
#endif

#if FIPS_VERSION3_GE(6,0,0)
    const unsigned int wolfCrypt_FIPS_cmac_ro_sanity[2] =
                                                     { 0x1a2b3c4d, 0x00000003 };
    int wolfCrypt_FIPS_CMAC_sanity(void)
    {
        return 0;
    }
#endif

#ifdef WOLFSSL_HASH_KEEP
/* Some hardware have issues with update, this function stores the data to be
 * hashed into an array. Once ready, the Final operation is called on all of the
 * data to be hashed at once.
 * returns 0 on success
 */
int wc_CMAC_Grow(Cmac* cmac, const byte* in, int inSz)
{
    return _wc_Hash_Grow(&cmac->msg, &cmac->used, &cmac->len, in, inSz, NULL);
}
#endif /* WOLFSSL_HASH_KEEP */

#if !defined(NO_AES) && defined(WOLFSSL_AES_DIRECT)
/* Used by AES-SIV. See aes.c. */
void ShiftAndXorRb(byte* out, byte* in)
{
    int i, j, xorRb;
    int mask = 0, last = 0;
    byte Rb = 0x87;

    xorRb = (in[0] & 0x80) != 0;

    for (i = 1, j = WC_AES_BLOCK_SIZE - 1; i <= WC_AES_BLOCK_SIZE; i++, j--) {
        last = (in[j] & 0x80) ? 1 : 0;
        out[j] = (byte)((in[j] << 1) | mask);
        mask = last;
        if (xorRb) {
            out[j] ^= Rb;
            Rb = 0;
        }
    }
}
#endif /* !NO_AES && WOLFSSL_AES_DIRECT */

/* returns 0 on success */
int wc_InitCmac_ex(Cmac* cmac, const byte* key, word32 keySz,
                int type, void* unused, void* heap, int devId)
{
    int ret = 0;
#if defined(WOLFSSL_SE050) && defined(WOLFSSL_SE050_CRYPT)
    byte useSW = 0;
#endif

    (void)unused;
    (void)heap;

    if (cmac == NULL || type != WC_CMAC_AES) {
        return BAD_FUNC_ARG;
    }

#if defined(WOLFSSL_SE050) && defined(WOLFSSL_SE050_CRYPT)
    /* save if we should use SW crypt, restore after memset */
    useSW = cmac->useSWCrypt;
#endif
    XMEMSET(cmac, 0, sizeof(Cmac));

#ifdef WOLF_CRYPTO_CB
    /* Set devId regardless of value (invalid or not) */
    cmac->devId = devId;
    #ifndef WOLF_CRYPTO_CB_FIND
    if (devId != INVALID_DEVID)
    #endif
    {
        cmac->devCtx = NULL;

        ret = wc_CryptoCb_Cmac(cmac, key, keySz, NULL, 0, NULL, NULL,
                type, unused);
        if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
            return ret;
        /* fall-through when unavailable */
    }
#else
    (void)devId;
#endif

    if (key == NULL || keySz == 0) {
        return BAD_FUNC_ARG;
    }

    switch (type) {
#if !defined (NO_AES) && defined(WOLFSSL_AES_DIRECT)
    case WC_CMAC_AES:
        cmac->type = WC_CMAC_AES;
        ret = wc_AesInit(&cmac->aes, heap, devId);

    #if defined(WOLFSSL_SE050) && defined(WOLFSSL_SE050_CRYPT)
        cmac->useSWCrypt = useSW;
        if (cmac->useSWCrypt == 1) {
            cmac->aes.useSWCrypt = 1;
        }
    #endif

        if (ret == 0) {
            ret = wc_AesSetKey(&cmac->aes, key, keySz, NULL, AES_ENCRYPTION);
        }

        if (ret == 0) {
            byte l[WC_AES_BLOCK_SIZE];

            XMEMSET(l, 0, WC_AES_BLOCK_SIZE);
            ret = wc_AesEncryptDirect(&cmac->aes, l, l);
            if (ret == 0) {
                ShiftAndXorRb(cmac->k1, l);
                ShiftAndXorRb(cmac->k2, cmac->k1);
                ForceZero(l, WC_AES_BLOCK_SIZE);
            }
        }
        break;
#endif /* !NO_AES && WOLFSSL_AES_DIRECT */
    default:
        return BAD_FUNC_ARG;
    }

    return ret;
}


int wc_InitCmac(Cmac* cmac, const byte* key, word32 keySz,
                int type, void* unused)
{
#ifdef WOLFSSL_QNX_CAAM
    int devId = WOLFSSL_CAAM_DEVID;
#else
    int devId = INVALID_DEVID;
#endif
    return wc_InitCmac_ex(cmac, key, keySz, type, unused, NULL, devId);
}



int wc_CmacUpdate(Cmac* cmac, const byte* in, word32 inSz)
{
    int ret = 0;

    if ((cmac == NULL) || (in == NULL && inSz != 0)) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLF_CRYPTO_CB
    #ifndef WOLF_CRYPTO_CB_FIND
    if (cmac->devId != INVALID_DEVID)
    #endif
    {
        ret = wc_CryptoCb_Cmac(cmac, NULL, 0, in, inSz,
                NULL, NULL, cmac->type, NULL);
        if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
            return ret;
        /* fall-through when unavailable */
    }
#endif

    /* Clear CRYPTOCB_UNAVAILABLE return code */
    ret = 0;

    switch (cmac->type) {
#if !defined(NO_AES) && defined(WOLFSSL_AES_DIRECT)
    case WC_CMAC_AES:
    {
        while ((ret == 0) && (inSz != 0)) {
            word32 add = min(inSz, WC_AES_BLOCK_SIZE - cmac->bufferSz);
            XMEMCPY(&cmac->buffer[cmac->bufferSz], in, add);

            cmac->bufferSz += add;
            in += add;
            inSz -= add;

            if (cmac->bufferSz == WC_AES_BLOCK_SIZE && inSz != 0) {
                if (cmac->totalSz != 0) {
                    xorbuf(cmac->buffer, cmac->digest, WC_AES_BLOCK_SIZE);
                }
                ret = wc_AesEncryptDirect(&cmac->aes, cmac->digest,
                        cmac->buffer);
                if (ret == 0) {
                    cmac->totalSz += WC_AES_BLOCK_SIZE;
                    cmac->bufferSz = 0;
                }
            }
        }
    }; break;
#endif /* !NO_AES && WOLFSSL_AES_DIRECT */
    default:
        ret = BAD_FUNC_ARG;
    }
    return ret;
}

int wc_CmacFree(Cmac* cmac)
{
    if (cmac == NULL)
        return BAD_FUNC_ARG;
#if defined(WOLFSSL_HASH_KEEP)
    /* TODO: msg is leaked if wc_CmacFinal() is not called
     * e.g. when multiple calls to wc_CmacUpdate() and one fails but
     * wc_CmacFinal() not called. */
    XFREE(cmac->msg, cmac->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    switch (cmac->type) {
#if !defined(NO_AES) && defined(WOLFSSL_AES_DIRECT)
    case WC_CMAC_AES:
        wc_AesFree(&cmac->aes);
        break;
#endif /* !NO_AES && WOLFSSL_AES_DIRECT */
    default:
        /* Nothing to do */
        (void)cmac;
    }
    ForceZero(cmac, sizeof(Cmac));
    return 0;
}

int wc_CmacFinalNoFree(Cmac* cmac, byte* out, word32* outSz)
{
    int ret = 0;

    if (cmac == NULL || out == NULL || outSz == NULL) {
        return BAD_FUNC_ARG;
    }
    if (*outSz < WC_CMAC_TAG_MIN_SZ || *outSz > WC_CMAC_TAG_MAX_SZ) {
        return BUFFER_E;
    }

#ifdef WOLF_CRYPTO_CB
    #ifndef WOLF_CRYPTO_CB_FIND
    if (cmac->devId != INVALID_DEVID)
    #endif
    {
        ret = wc_CryptoCb_Cmac(cmac, NULL, 0, NULL, 0, out, outSz, cmac->type,
                NULL);
        if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
            return ret;

        /* Clear CRYPTOCB_UNAVAILABLE return code */
       ret = 0;

        /* fall-through when unavailable */
    }
#endif
    if (ret == 0) {
        switch (cmac->type) {
    #if !defined(NO_AES) && defined(WOLFSSL_AES_DIRECT)
        case WC_CMAC_AES:
        {
            const byte* subKey;
            word32 remainder;

            if (cmac->bufferSz == WC_AES_BLOCK_SIZE) {
                subKey = cmac->k1;
            }
            else {
                /* ensure we will have a valid remainder value */
                if (cmac->bufferSz > WC_AES_BLOCK_SIZE) {
                    ret = BAD_STATE_E;
                    break;
                }
                remainder = WC_AES_BLOCK_SIZE - cmac->bufferSz;

                if (remainder == 0) {
                    remainder = WC_AES_BLOCK_SIZE;
                }
                if (remainder > 1) {
                    XMEMSET(cmac->buffer + WC_AES_BLOCK_SIZE - remainder, 0,
                            remainder);
                }

                cmac->buffer[WC_AES_BLOCK_SIZE - remainder] = 0x80;
                subKey = cmac->k2;
            }
            xorbuf(cmac->buffer, cmac->digest, WC_AES_BLOCK_SIZE);
            xorbuf(cmac->buffer, subKey, WC_AES_BLOCK_SIZE);
            ret = wc_AesEncryptDirect(&cmac->aes, cmac->digest, cmac->buffer);
            if (ret == 0) {
                XMEMCPY(out, cmac->digest, *outSz);
            }
        }; break;
    #endif /* !NO_AES && WOLFSSL_AES_DIRECT */
        default:
            ret = BAD_FUNC_ARG;
        }
    }
    return ret;
}

int wc_CmacFinal(Cmac* cmac, byte* out, word32* outSz)
{
    int ret = 0;

    if (cmac == NULL)
        return BAD_FUNC_ARG;
    ret = wc_CmacFinalNoFree(cmac, out, outSz);
    (void)wc_CmacFree(cmac);
    return ret;
}

#if !defined(NO_AES) && defined(WOLFSSL_AES_DIRECT)
int wc_AesCmacGenerate_ex(Cmac* cmac,
                          byte* out, word32* outSz,
                          const byte* in, word32 inSz,
                          const byte* key, word32 keySz,
                          void* heap, int devId)
{
    int ret = 0;

    if (cmac == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLF_CRYPTO_CB
    /* Set devId regardless of value (invalid or not) */
    cmac->devId = devId;
    #ifndef WOLF_CRYPTO_CB_FIND
    if (devId != INVALID_DEVID)
    #endif
    {
        ret = wc_CryptoCb_Cmac(cmac, key, keySz, in, inSz, out, outSz,
                WC_CMAC_AES, NULL);
        if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
            return ret;

         /* Clear CRYPTOCB_UNAVAILABLE return code */
        ret = 0;

        /* fall-through when unavailable */
    }
#endif

    if ( ((out == NULL) && (outSz != NULL) && (*outSz > 0))
         || (in == NULL && inSz > 0)
         || (key == NULL && keySz > 0))  {
        return BAD_FUNC_ARG;
    }

    /* Init step is optional */
    if (key != NULL) {
        ret = wc_InitCmac_ex(cmac, key, keySz, WC_CMAC_AES, NULL, heap, devId);
    }
    if (ret == 0) {
        ret = wc_CmacUpdate(cmac, in, inSz);
        /* Ensure we are freed and zeroed if not calling wc_CmacFinal */
        if (ret != 0) {
            (void)wc_CmacFree(cmac);
        }
    }
    if (ret == 0) {
        ret = wc_CmacFinal(cmac, out, outSz);
    }

    return ret;
}


int wc_AesCmacGenerate(byte* out, word32* outSz,
                       const byte* in, word32 inSz,
                       const byte* key, word32 keySz)
{
    int ret = 0;
#ifdef WOLFSSL_SMALL_STACK
    Cmac *cmac;
#else
    Cmac cmac[1];
#endif

    if (out == NULL || (in == NULL && inSz > 0) || key == NULL || keySz == 0) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_SMALL_STACK
    if ((cmac = (Cmac *)XMALLOC(sizeof *cmac, NULL,
                                DYNAMIC_TYPE_CMAC)) == NULL) {
        return MEMORY_E;
    }
#endif

#ifdef WOLFSSL_CHECK_MEM_ZERO
    XMEMSET(((unsigned char *)cmac) + sizeof(Aes), 0xff,
        sizeof(Cmac) - sizeof(Aes));
    /* Aes part is checked by wc_AesFree. */
    wc_MemZero_Add("wc_AesCmacGenerate_ex cmac",
        ((unsigned char *)cmac) + sizeof(Aes), sizeof(Cmac) - sizeof(Aes));
#endif

    ret = wc_AesCmacGenerate_ex(cmac,
                                out, outSz,
                                in, inSz,
                                key, keySz,
                                NULL,
                                INVALID_DEVID);


#ifdef WOLFSSL_SMALL_STACK
    XFREE(cmac, NULL, DYNAMIC_TYPE_CMAC);
#elif defined(WOLFSSL_CHECK_MEM_ZERO)
    wc_MemZero_Check(cmac, sizeof(Cmac));
#endif

    return ret;
}


int wc_AesCmacVerify_ex(Cmac* cmac,
                        const byte* check, word32 checkSz,
                        const byte* in, word32 inSz,
                        const byte* key, word32 keySz,
                        void* heap, int devId)
{
    int ret = 0;
    byte a[WC_AES_BLOCK_SIZE];
    word32 aSz = sizeof(a);
    int compareRet;

    if (cmac == NULL || check == NULL || checkSz == 0 ||
            (in == NULL && inSz != 0)) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(a, 0, aSz);
    ret = wc_AesCmacGenerate_ex(cmac,
                                a, &aSz,
                                in, inSz,
                                key, keySz,
                                heap,
                                devId);
    if (ret == 0) {
        compareRet = ConstantCompare(check, a, (int)min(checkSz, aSz));
        ret = compareRet ? 1 : 0;
    }

    return ret;
}


int wc_AesCmacVerify(const byte* check, word32 checkSz,
                     const byte* in, word32 inSz,
                     const byte* key, word32 keySz)
{
    int ret = 0;
#ifdef WOLFSSL_SMALL_STACK
    Cmac *cmac;
#else
    Cmac cmac[1];
#endif

    if (check == NULL || checkSz == 0 || (in == NULL && inSz > 0) ||
            key == NULL || keySz == 0) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_SMALL_STACK
    if ((cmac = (Cmac *)XMALLOC(sizeof *cmac, NULL,
                                DYNAMIC_TYPE_CMAC)) == NULL) {
        return MEMORY_E;
    }
#endif

#ifdef WOLFSSL_CHECK_MEM_ZERO
    XMEMSET(((unsigned char *)cmac) + sizeof(Aes), 0xff,
        sizeof(Cmac) - sizeof(Aes));
    /* Aes part is checked by wc_AesFree. */
    wc_MemZero_Add("wc_AesCmacGenerate_ex cmac",
        ((unsigned char *)cmac) + sizeof(Aes), sizeof(Cmac) - sizeof(Aes));
#endif

    ret = wc_AesCmacVerify_ex(cmac,
                              check, checkSz,
                              in, inSz,
                              key, keySz,
                              NULL,
                              INVALID_DEVID);

#ifdef WOLFSSL_SMALL_STACK
    XFREE(cmac, NULL, DYNAMIC_TYPE_CMAC);
#elif defined(WOLFSSL_CHECK_MEM_ZERO)
    wc_MemZero_Check(cmac, sizeof(Cmac));
#endif

    return ret;
}
#endif /* !NO_AES && WOLFSSL_AES_DIRECT */

#endif /* WOLFSSL_CMAC */
