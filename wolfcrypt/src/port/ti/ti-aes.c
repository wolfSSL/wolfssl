/* port/ti/ti-aes.c
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
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

#if !defined(NO_AES) && defined(WOLFSSL_TI_CRYPT)

#include <stdbool.h>
#include <stdint.h>

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/port/ti/ti-ccm.h>

#include "inc/hw_aes.h"
#include "inc/hw_memmap.h"
#include "inc/hw_ints.h"
#include "driverlib/aes.h"
#include "driverlib/sysctl.h"
#include "driverlib/rom_map.h"
#include "driverlib/rom.h"

#define AES_CFG_MODE_CTR_NOCTR (AES_CFG_MODE_CTR + 100)
#define IS_ALIGN16(p) (((unsigned int)(p) & 0xf) == 0)
#define ROUNDUP_16(n) ((n+15) & 0xfffffff0)
#ifndef TI_BUFFSIZE
#define TI_BUFFSIZE 1024
#endif

static int AesSetIV(Aes* aes, const byte* iv)
{
    if (aes == NULL)
        return BAD_FUNC_ARG;

    if (iv)
        XMEMCPY(aes->reg, iv, AES_BLOCK_SIZE);
    else
        XMEMSET(aes->reg,  0, AES_BLOCK_SIZE);

    return 0;
}

int wc_AesSetKey(Aes* aes, const byte* key, word32 len, const byte* iv, int dir)
{
    if (!wolfSSL_TI_CCMInit())
        return 1;
    if ((aes == NULL) || (key == NULL))
        return BAD_FUNC_ARG;
    if (!((dir == AES_ENCRYPTION) || (dir == AES_DECRYPTION)))
        return BAD_FUNC_ARG;

    switch (len) {
    #ifdef WOLFSSL_AES_128
        case 16:
            break;
    #endif
    #ifdef WOLFSSL_AES_192
        case 24:
            break;
    #endif
    #ifdef WOLFSSL_AES_256
        case 32:
            break;
    #endif
        default:
            return BAD_FUNC_ARG;
    }
    aes->keylen = len;
    aes->rounds = len / 4 + 6;

    XMEMCPY(aes->key, key, len);
#ifdef WOLFSSL_AES_COUNTER
    aes->left = 0;
#endif
    return AesSetIV(aes, iv);
}

static int AesAlign16(Aes* aes, byte* out, const byte* in, word32 sz,
    word32 dir, word32 mode)
{
    /* Processed aligned chunk to HW AES */
    wolfSSL_TI_lockCCM();
    ROM_AESReset(AES_BASE);
    ROM_AESConfigSet(AES_BASE, (aes->keylen-8 | dir |
        (mode == AES_CFG_MODE_CTR_NOCTR ? AES_CFG_MODE_CTR : mode)));
    ROM_AESIVSet(AES_BASE, (uint32_t *)aes->reg);
    ROM_AESKey1Set(AES_BASE, (uint32_t *)aes->key, aes->keylen-8);
    if ((dir == AES_CFG_DIR_DECRYPT)&& (mode == AES_CFG_MODE_CBC)) {
        /* if input and output same will overwrite input iv */
        XMEMCPY(aes->tmp, in + sz - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    }
    ROM_AESDataProcess(AES_BASE, (uint32_t *)in, (uint32_t *)out, sz);
    wolfSSL_TI_unlockCCM();

    /* store iv for next call */
    if (mode == AES_CFG_MODE_CBC) {
        if (dir == AES_CFG_DIR_ENCRYPT)
            XMEMCPY(aes->reg, out + sz - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
        else
            XMEMCPY(aes->reg, aes->tmp, AES_BLOCK_SIZE);
    }

    if (mode == AES_CFG_MODE_CTR) {
        do {
            int i;
            for (i = AES_BLOCK_SIZE - 1; i >= 0; i--) {
                 if (++((byte *)aes->reg)[i])
                     break;
            }
            sz -= AES_BLOCK_SIZE;
        } while ((int)sz > 0);
    }

    return 0;
}

static int AesProcess(Aes* aes, byte* out, const byte* in, word32 sz,
    word32 dir, word32 mode)
{
    const byte * in_p; byte * out_p;
    word32 size;
    byte buff[TI_BUFFSIZE];

    if ((aes == NULL) || (in == NULL) || (out == NULL))
        return BAD_FUNC_ARG;
    if (sz % AES_BLOCK_SIZE)
        return BAD_FUNC_ARG;

    while (sz > 0) {
        size = sz; in_p = in; out_p = out;
        if (!IS_ALIGN16(in)) {
            size = sz > TI_BUFFSIZE ? TI_BUFFSIZE : sz;
            XMEMCPY(buff, in, size);
            in_p = (const byte *)buff;
        }
        if (!IS_ALIGN16(out)) {
            size = sz > TI_BUFFSIZE ? TI_BUFFSIZE : sz;
            out_p = buff;
        }

        AesAlign16(aes, out_p, in_p, size, dir, mode);

        if (!IS_ALIGN16(out)) {
            XMEMCPY(out, buff, size);
        }
        sz -= size; in += size; out += size;
    }

    return 0;
}

int wc_AesCbcEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    return AesProcess(aes, out, in, sz, AES_CFG_DIR_ENCRYPT, AES_CFG_MODE_CBC);
}

int wc_AesCbcDecrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    return AesProcess(aes, out, in, sz, AES_CFG_DIR_DECRYPT, AES_CFG_MODE_CBC);
}

#ifdef WOLFSSL_AES_COUNTER
int wc_AesCtrEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    char out_block[AES_BLOCK_SIZE];
    int odd;
    int even;
    char *tmp; /* (char *)aes->tmp, for short */
    int ret;

    tmp = (char *)aes->tmp;
    if (aes->left) {
        if ((aes->left + sz) >= AES_BLOCK_SIZE) {
            odd = AES_BLOCK_SIZE - aes->left;
        } else {
            odd = sz;
        }
        XMEMCPY(tmp+aes->left, in, odd);
        if ((odd+aes->left) == AES_BLOCK_SIZE) {
            ret = AesProcess(aes, (byte *)out_block, (byte const *)tmp, AES_BLOCK_SIZE,
                        AES_CFG_DIR_ENCRYPT, AES_CFG_MODE_CTR);
            if (ret != 0)
                return ret;
            XMEMCPY(out, out_block+aes->left, odd);
            aes->left = 0;
            XMEMSET(tmp, 0x0, AES_BLOCK_SIZE);
        }
        in += odd;
        out+= odd;
        sz -= odd;
    }
    odd = sz % AES_BLOCK_SIZE;  /* if there is tail fragment */
    if (sz / AES_BLOCK_SIZE) {
        even = (sz/AES_BLOCK_SIZE)*AES_BLOCK_SIZE;
        ret = AesProcess(aes, out, in, even, AES_CFG_DIR_ENCRYPT, AES_CFG_MODE_CTR);
        if (ret != 0)
            return ret;
        out += even;
        in  += even;
    }
    if (odd) {
        XMEMSET(tmp+aes->left, 0x0, AES_BLOCK_SIZE - aes->left);
        XMEMCPY(tmp+aes->left, in, odd);
        ret = AesProcess(aes, (byte *)out_block, (byte const *)tmp, AES_BLOCK_SIZE,
                    AES_CFG_DIR_ENCRYPT,
                    AES_CFG_MODE_CTR_NOCTR /* Counter mode without counting IV */
                    );
        if (ret != 0)
            return ret;
        XMEMCPY(out, out_block+aes->left,odd);
        aes->left += odd;
    }
    return 0;
}
#endif /* WOLFSSL_AES_COUNTER */

/* AES-DIRECT */
#if defined(WOLFSSL_AES_DIRECT)
int wc_AesEncryptDirect(Aes* aes, byte* out, const byte* in)
{
    return AesProcess(aes, out, in, AES_BLOCK_SIZE, AES_CFG_DIR_ENCRYPT,
        AES_CFG_MODE_CBC);
}
int wc_AesDecryptDirect(Aes* aes, byte* out, const byte* in)
{
    return AesProcess(aes, out, in, AES_BLOCK_SIZE, AES_CFG_DIR_DECRYPT,
        AES_CFG_MODE_CBC);
}
int wc_AesSetKeyDirect(Aes* aes, const byte* key, word32 len, const byte* iv,
    int dir)
{
    return wc_AesSetKey(aes, key, len, iv, dir);
}
#endif /* WOLFSSL_AES_DIRECT */


#if defined(HAVE_AESGCM) || defined(HAVE_AESCCM)

static int AesAuthSetKey(Aes* aes, const byte* key, word32 keySz)
{
    byte nonce[AES_BLOCK_SIZE];

    if ((aes == NULL) || (key == NULL))
        return BAD_FUNC_ARG;
    if (!((keySz == 16) || (keySz == 24) || (keySz == 32)))
        return BAD_FUNC_ARG;

    XMEMSET(nonce, 0, sizeof(nonce));
    return wc_AesSetKey(aes, key, keySz, nonce, AES_ENCRYPTION);
}


static int AesAuthArgCheck(Aes* aes, byte* out, const byte* in, word32 inSz,
    const byte* nonce, word32 nonceSz,
    const byte* authTag, word32 authTagSz,
    const byte* authIn, word32 authInSz, word32 *M, word32 *L)
{
    (void) authInSz;
    if ((aes == NULL) || (nonce == NULL) || (authTag== NULL) || (authIn == NULL))
        return BAD_FUNC_ARG;
    if ((inSz != 0) && ((out == NULL) || (in == NULL)))
        return BAD_FUNC_ARG;

    switch (authTagSz) {
    case 4:
        *M = AES_CFG_CCM_M_4; break;
    case 6:
        *M = AES_CFG_CCM_M_6; break;
    case 8:
        *M = AES_CFG_CCM_M_8; break;
    case 10:
        *M = AES_CFG_CCM_M_10; break;
    case 12:
        *M = AES_CFG_CCM_M_12; break;
    case 14:
        *M = AES_CFG_CCM_M_14; break;
    case 16:
        *M = AES_CFG_CCM_M_16; break;
    default:
        return 1;
    }

    switch (nonceSz) {
    case 7:
        *L = AES_CFG_CCM_L_8; break;
    case 8:
        *L = AES_CFG_CCM_L_7; break;
    case 9:
        *L = AES_CFG_CCM_L_6; break;
    case  10:
        *L = AES_CFG_CCM_L_5; break;
    case 11:
        *L = AES_CFG_CCM_L_4; break;
    case 12:
        *L = AES_CFG_CCM_L_3; break;
    case 13:
        *L = AES_CFG_CCM_L_2; break;
    case 14:
        *L = AES_CFG_CCM_L_1; break;
    default:
        return 1;
    }
    return 0;
}

static void AesAuthSetIv(Aes *aes, const byte *nonce, word32 len, word32 L,
    int mode)
{
    if (mode == AES_CFG_MODE_CCM) {
        XMEMSET(aes->reg, 0, 16);
        switch (L) {
        case AES_CFG_CCM_L_8:
            aes->reg[0] = 0x7; break;
        case AES_CFG_CCM_L_7:
            aes->reg[0] = 0x6; break;
        case AES_CFG_CCM_L_6:
            aes->reg[0] = 0x5; break;
        case AES_CFG_CCM_L_5:
            aes->reg[0] = 0x4; break;
        case AES_CFG_CCM_L_4:
            aes->reg[0] = 0x3; break;
        case AES_CFG_CCM_L_3:
            aes->reg[0] = 0x2; break;
        case AES_CFG_CCM_L_2:
            aes->reg[0] = 0x1; break;
        case AES_CFG_CCM_L_1:
            aes->reg[0] = 0x0; break;
        }
        XMEMCPY(((byte *)aes->reg)+1, nonce, len);
    }
    else {
        byte *b = (byte *)aes->reg;
        XMEMSET(aes->reg, 0, AES_BLOCK_SIZE);
        if (nonce != NULL && len < AES_BLOCK_SIZE)
            XMEMCPY(aes->reg, nonce, len);
        b[AES_BLOCK_SIZE-4] = 0;
        b[AES_BLOCK_SIZE-3] = 0;
        b[AES_BLOCK_SIZE-2] = 0;
        b[AES_BLOCK_SIZE-1] = 1;
    }
}

static int AesAuthEncrypt(Aes* aes, byte* out, const byte* in, word32 inSz,
                              const byte* nonce, word32 nonceSz,
                              byte* authTag, word32 authTagSz,
                              const byte* authIn, word32 authInSz, int mode)
{
    int ret;
    word32 M, L;
    byte *in_a,     *in_save = NULL;
    byte *out_a,    *out_save = NULL;
    byte *authIn_a, *authIn_save = NULL;
    byte *nonce_a,  *nonce_save = NULL;
    word32 tmpTag[4];

    ret = AesAuthArgCheck(aes, out, in, inSz, nonce, nonceSz, authTag,
        authTagSz, authIn, authInSz, &M, &L);
    if (ret == BAD_FUNC_ARG) {
        return ret;
    }

    /* 16 byte padding */
    in_save = NULL; out_save = NULL; authIn_save = NULL; nonce_save = NULL;
    if (IS_ALIGN16(inSz)) {
        in_save = NULL; in_a = (byte *)in;
        out_save = NULL; out_a = out;
    }
    else {
        in_save = XMALLOC(ROUNDUP_16(inSz), NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (in_save == NULL) { ret = MEMORY_E; goto exit; }
        in_a = in_save;
        XMEMSET(in_a, 0, ROUNDUP_16(inSz));
        XMEMCPY(in_a, in, inSz);

        out_save = XMALLOC(ROUNDUP_16(inSz), NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (out_save == NULL) { ret = MEMORY_E; goto exit; }
        out_a = out_save;
    }

    if (IS_ALIGN16(authInSz)) {
        authIn_save = NULL; authIn_a = (byte *)authIn;
    }
    else {
        authIn_save = XMALLOC(ROUNDUP_16(authInSz), NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (authIn_save == NULL) { ret = MEMORY_E; goto exit; }

        authIn_a = authIn_save;
        XMEMSET(authIn_a, 0, ROUNDUP_16(authInSz));
        XMEMCPY(authIn_a, authIn, authInSz);
    }

    if (IS_ALIGN16(nonceSz)) {
        nonce_save = NULL;
        nonce_a = (byte *)nonce;
    }
    else {
        nonce_save = XMALLOC(ROUNDUP_16(nonceSz), NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (nonce_save == NULL) { ret = MEMORY_E; goto exit; }

        nonce_a = nonce_save;
        XMEMSET(nonce_a, 0, ROUNDUP_16(nonceSz));
        XMEMCPY(nonce_a, nonce, nonceSz);
    }

    /* do aes-ccm */
    AesAuthSetIv(aes, nonce, nonceSz, L, mode);
    ROM_AESReset(AES_BASE);
    ROM_AESConfigSet(AES_BASE, (aes->keylen-8 | AES_CFG_DIR_ENCRYPT |
                                AES_CFG_CTR_WIDTH_128 |
                                mode | ((mode== AES_CFG_MODE_CCM) ? (L | M) : 0 )));
    ROM_AESIVSet(AES_BASE, aes->reg);
    ROM_AESKey1Set(AES_BASE, aes->key, aes->keylen-8);
    ret = ROM_AESDataProcessAuth(AES_BASE, (unsigned int*)in_a, (unsigned int *)out_a, inSz,
                           (unsigned int*)authIn_a, authInSz, (unsigned int *)tmpTag);
    if (ret == false) {
        XMEMSET(out, 0, inSz);
        XMEMSET(authTag, 0, authTagSz);
    } else {
        XMEMCPY(out, out_a, inSz);
        XMEMCPY(authTag, tmpTag, authTagSz);
    }

exit:
    if (in_save)    XFREE(in_save, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (out_save)   XFREE(out_save, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (authIn_save)XFREE(authIn_save, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (nonce_save) XFREE(nonce_save, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return 0;
}

static int AesAuthDecrypt(Aes* aes, byte* out, const byte* in, word32 inSz,
                              const byte* nonce, word32 nonceSz,
                              const byte* authTag, word32 authTagSz,
                              const byte* authIn, word32 authInSz, int mode)
{
    int ret;
    word32 M, L;
    byte *in_a,     *in_save = NULL;
    byte *out_a,    *out_save = NULL;
    byte *authIn_a, *authIn_save = NULL;
    byte *nonce_a,  *nonce_save = NULL;
    word32 tmpTag[4];

    ret = AesAuthArgCheck(aes, out, in, inSz, nonce, nonceSz, authTag,
        authTagSz, authIn, authInSz, &M, &L);
    if (ret == BAD_FUNC_ARG) {
        return ret;
    }

    /* 16 byte padding */
    in_save = NULL; out_save = NULL; authIn_save = NULL; nonce_save = NULL;
    if (IS_ALIGN16(inSz)) {
        in_save = NULL; in_a = (byte *)in;
        out_save = NULL; out_a = out;
    }
    else {
        in_save = XMALLOC(ROUNDUP_16(inSz), NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (in_save == NULL) { ret = MEMORY_E; goto exit; }
        in_a = in_save;
        XMEMSET(in_a, 0, ROUNDUP_16(inSz));
        XMEMCPY(in_a, in, inSz);

        out_save = XMALLOC(ROUNDUP_16(inSz), NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (out_save == NULL) { ret = MEMORY_E; goto exit; }
        out_a = out_save;
    }

    if (IS_ALIGN16(authInSz)) {
        authIn_save = NULL; authIn_a = (byte *)authIn;
    }
    else {
        authIn_save = XMALLOC(ROUNDUP_16(authInSz), NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (authIn_save == NULL) { ret = MEMORY_E; goto exit; }

        authIn_a = authIn_save;
        XMEMSET(authIn_a, 0, ROUNDUP_16(authInSz));
        XMEMCPY(authIn_a, authIn, authInSz);
    }

    if (IS_ALIGN16(nonceSz)) {
        nonce_save = NULL; nonce_a = (byte *)nonce;
    }
    else {
        nonce_save = XMALLOC(ROUNDUP_16(nonceSz), NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (nonce_save == NULL) { ret = MEMORY_E; goto exit; }

        nonce_a = nonce_save;
        XMEMSET(nonce_a, 0, ROUNDUP_16(nonceSz));
        XMEMCPY(nonce_a, nonce, nonceSz);
    }

    /* do aes-ccm */
    AesAuthSetIv(aes, nonce, nonceSz, L, mode);
    ROM_AESReset(AES_BASE);
    ROM_AESConfigSet(AES_BASE, (aes->keylen-8 | AES_CFG_DIR_DECRYPT |
                                AES_CFG_CTR_WIDTH_128 |
                                  mode | ((mode== AES_CFG_MODE_CCM) ? (L | M) : 0 )));
    ROM_AESIVSet(AES_BASE, aes->reg);
    ROM_AESKey1Set(AES_BASE, aes->key, aes->keylen-8);
    ret = ROM_AESDataProcessAuth(AES_BASE, (unsigned int*)in_a, (unsigned int *)out_a, inSz,
                           (unsigned int*)authIn_a, authInSz, (unsigned int *)tmpTag);
    if ((ret == false) || (XMEMCMP(authTag, tmpTag, authTagSz) != 0)) {
        XMEMSET(out, 0, inSz);
        ret = false;
    } else {
        XMEMCPY(out, out_a, inSz);
    }

exit:
    if (in_save)    XFREE(in_save, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (out_save)   XFREE(out_save, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (authIn_save)XFREE(authIn_save, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (nonce_save) XFREE(nonce_save, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return ret==true ? 0 : 1;
}
#endif /* HAVE_AESGCM || HAVE_AESCCM */

#ifdef HAVE_AESGCM
int wc_AesGcmSetKey(Aes* aes, const byte* key, word32 len)
{
    return AesAuthSetKey(aes, key, len);
}

int wc_AesGcmEncrypt(Aes* aes, byte* out, const byte* in, word32 sz,
                              const byte* iv, word32 ivSz,
                              byte* authTag, word32 authTagSz,
                              const byte* authIn, word32 authInSz)
{
    if (authTagSz < WOLFSSL_MIN_AUTH_TAG_SZ) {
        return BAD_FUNC_ARG;
    }
    return AesAuthEncrypt(aes, out, in, sz, iv, ivSz, authTag, authTagSz,
                              authIn, authInSz, AES_CFG_MODE_GCM_HY0CALC);
}
int wc_AesGcmDecrypt(Aes* aes, byte* out, const byte* in, word32 sz,
                              const byte* iv, word32 ivSz,
                              const byte* authTag, word32 authTagSz,
                              const byte* authIn, word32 authInSz)
{
    return AesAuthDecrypt(aes, out, in, sz, iv, ivSz, authTag, authTagSz,
                              authIn, authInSz, AES_CFG_MODE_GCM_HY0CALC);
}

int wc_GmacSetKey(Gmac* gmac, const byte* key, word32 len)
{
    return AesAuthSetKey(&gmac->aes, key, len);
}

int wc_GmacUpdate(Gmac* gmac, const byte* iv, word32 ivSz,
                              const byte* authIn, word32 authInSz,
                              byte* authTag, word32 authTagSz)
{
    return AesAuthEncrypt(&gmac->aes, NULL, NULL, 0, iv, ivSz, authTag, authTagSz,
                              authIn, authInSz, AES_CFG_MODE_GCM_HY0CALC);
}
#endif /* HAVE_AESGCM */

#ifdef HAVE_AESCCM
int wc_AesCcmSetKey(Aes* aes, const byte* key, word32 keySz)
{
    return AesAuthSetKey(aes, key, keySz);
}

int wc_AesCcmEncrypt(Aes* aes, byte* out, const byte* in, word32 inSz,
                              const byte* nonce, word32 nonceSz,
                              byte* authTag, word32 authTagSz,
                              const byte* authIn, word32 authInSz)
{
    return AesAuthEncrypt(aes, out, in, inSz, nonce, nonceSz, authTag, authTagSz,
                              authIn, authInSz, AES_CFG_MODE_CCM);
}

int wc_AesCcmDecrypt(Aes* aes, byte* out, const byte* in, word32 inSz,
                              const byte* nonce, word32 nonceSz,
                              const byte* authTag, word32 authTagSz,
                              const byte* authIn, word32 authInSz)
{
    return AesAuthDecrypt(aes, out, in, inSz, nonce, nonceSz, authTag, authTagSz,
                              authIn, authInSz, AES_CFG_MODE_CCM);
}
#endif /* HAVE_AESCCM */

int wc_AesInit(Aes* aes, void* heap, int devId)
{
    if (aes == NULL)
        return BAD_FUNC_ARG;

    aes->heap = heap;
    (void)devId;

    return 0;
}

void wc_AesFree(Aes* aes)
{
    (void)aes;
}

#endif /* !NO_AES && WOLFSSL_TI_CRYPT */
