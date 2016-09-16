/* cavium-nitrox.c
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef HAVE_CAVIUM

#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/internal.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#ifndef NO_RSA
    #include <wolfssl/wolfcrypt/rsa.h>
#endif
#ifndef NO_AES
    #include <wolfssl/wolfcrypt/aes.h>
#endif

#include <wolfssl/wolfcrypt/port/cavium/cavium_nitrox.h>
#include <netinet/in.h> /* For ntohs */

static CspHandle mLastDevHandle = INVALID_DEVID;

int NitroxTranslateResponseCode(int ret)
{
    switch (ret) {
        case EAGAIN:
        case ERR_REQ_PENDING:
            ret = WC_PENDING_E;
            break;
        case ERR_REQ_TIMEOUT:
            ret = WC_TIMEOUT_E;
            break;
        case 0:
            /* leave as-is */
            break;
        default:
            printf("NitroxTranslateResponseCode Unknown ret=%x\n", ret);
            ret = ASYNC_INIT_E;
    }
    return ret;
}


CspHandle NitroxGetDeviceHandle(void)
{
    return mLastDevHandle;
}
    
CspHandle NitroxOpenDevice(int dma_mode, int dev_id)
{
    mLastDevHandle = INVALID_DEVID;

#ifdef HAVE_CAVIUM_V
    (void)dma_mode;

    if (CspInitialize(dev_id, &mLastDevHandle)) {
        return -1;
    }

#else
    Csp1CoreAssignment core_assign;
    Uint32             device;

    if (CspInitialize(CAVIUM_DIRECT, CAVIUM_DEV_ID)) {
        return -1;
    }
    if (Csp1GetDevType(&device)) {
        return -1;
    }
    if (device != NPX_DEVICE) {
        if (ioctl(gpkpdev_hdlr[CAVIUM_DEV_ID], IOCTL_CSP1_GET_CORE_ASSIGNMENT,
        (Uint32 *)&core_assign)!= 0) {
            return -1;
        }
    }
    CspShutdown(CAVIUM_DEV_ID);

    mLastDevHandle = CspInitialize(dma_mode, dev_id);
    if (mLastDevHandle == 0) {
        mLastDevHandle = dev_id;
    }

#endif /* HAVE_CAVIUM_V */

    return mLastDevHandle;
}


int NitroxAllocContext(CaviumNitroxDev* nitrox, CspHandle devId,
    ContextType type)
{
    int ret;

    if (nitrox == NULL) {
        return -1;
    }

    /* If invalid handle provided, use last open one */
    if (devId == INVALID_DEVID) {
        devId = NitroxGetDeviceHandle();
    }

#ifdef HAVE_CAVIUM_V
    ret = CspAllocContext(devId, type, &nitrox->contextHandle);
#else
    ret = CspAllocContext(type, &nitrox->contextHandle, devId);
#endif
    if (ret != 0) {
        return -1;
    }

    nitrox->type = type;
    nitrox->devId = devId;

    return 0;
}

void NitroxFreeContext(CaviumNitroxDev* nitrox)
{
    if (nitrox == NULL) {
        return;
    }

#ifdef HAVE_CAVIUM_V
    CspFreeContext(nitrox->devId, nitrox->type, nitrox->contextHandle);
#else
    CspFreeContext(nitrox->type, nitrox->contextHandle, nitrox->devId);
#endif
}

void NitroxCloseDevice(CspHandle devId)
{
    if (devId >= 0) {
        CspShutdown(devId);
    }
}

#if defined(WOLFSSL_ASYNC_CRYPT)

int NitroxCheckRequest(CspHandle devId, CavReqId reqId)
{
    int ret = CspCheckForCompletion(devId, reqId);
    return NitroxTranslateResponseCode(ret);
}

int NitroxCheckRequests(CspHandle devId, CspMultiRequestStatusBuffer* req_stat_buf)
{
    int ret = CspGetAllResults(req_stat_buf, devId);
    return NitroxTranslateResponseCode(ret);   
}


#ifndef NO_RSA

int NitroxRsaExptMod(const byte* in, word32 inLen,
                     byte* exponent, word32 expLen,
                     byte* modulus, word32 modLen,
                     byte* out, word32* outLen, RsaKey* key)
{
    int ret;

    if (key == NULL || in == NULL || inLen == 0 || exponent == NULL ||
                                            modulus == NULL || out == NULL) {
        return BAD_FUNC_ARG;
    }

    (void)outLen;

#ifdef HAVE_CAVIUM_V
    ret = CspMe(key->asyncDev.dev.devId, CAVIUM_REQ_MODE, CAVIUM_SSL_GRP,
            CAVIUM_DPORT, modLen, expLen, inLen,
            modulus, exponent, (Uint8*)in, out,
            &key->asyncDev.dev.reqId);
    #if 0
    /* TODO: Try MeCRT */
    ret = CspMeCRT();
    #endif
#else
    /* Not implemented/supported */
    ret = NOT_COMPILED_IN;
#endif
    ret = NitroxTranslateResponseCode(ret);
    if (ret != 0) {
        return ret;
    }

    return ret;
}

int NitroxRsaPublicEncrypt(const byte* in, word32 inLen, byte* out,
                           word32 outLen, RsaKey* key)
{
    word32 ret;

    if (key == NULL || in == NULL || out == NULL || outLen < (word32)key->n.used) {
        return BAD_FUNC_ARG;
    }

#ifdef HAVE_CAVIUM_V
    ret = CspPkcs1v15Enc(key->asyncDev.dev.devId, CAVIUM_REQ_MODE, CAVIUM_SSL_GRP, CAVIUM_DPORT,
                         BT2, key->n.used, key->e.used,
                         (word16)inLen, key->n.dpraw, key->e.dpraw, (byte*)in, out,
                         &key->asyncDev.dev.reqId);
#else
    ret = CspPkcs1v15Enc(CAVIUM_REQ_MODE, BT2, key->n.used, key->e.used,
                         (word16)inLen, key->n.dpraw, key->e.dpraw, (byte*)in, out,
                         &key->asyncDev.dev.reqId, key->asyncDev.dev.devId);
#endif
    ret = NitroxTranslateResponseCode(ret);
    if (ret != 0) {
        return ret;
    }

    return key->n.used;
}


static INLINE void ato16(const byte* c, word16* u16)
{
    *u16 = (c[0] << 8) | (c[1]);
}

int NitroxRsaPrivateDecrypt(const byte* in, word32 inLen, byte* out,
                            word32 outLen, RsaKey* key)
{
    word32 ret;
    word16 outSz = (word16)outLen;

    if (key == NULL || in == NULL || out == NULL ||
                                                inLen != (word32)key->n.used) {
        return BAD_FUNC_ARG;
    }

#ifdef HAVE_CAVIUM_V
    ret = CspPkcs1v15CrtDec(key->asyncDev.dev.devId, CAVIUM_REQ_MODE, CAVIUM_SSL_GRP, CAVIUM_DPORT,
                            BT2, key->n.used, key->q.dpraw,
                            key->dQ.dpraw, key->p.dpraw, key->dP.dpraw, key->u.dpraw,
                            (byte*)in, &outSz, out, &key->asyncDev.dev.reqId);
#else
    ret = CspPkcs1v15CrtDec(CAVIUM_REQ_MODE, BT2, key->n.used, key->q.dpraw,
                            key->dQ.dpraw, key->p.dpraw, key->dP.dpraw, key->u.dpraw,
                            (byte*)in, &outSz, out, &key->asyncDev.dev.reqId,
                            key->asyncDev.dev.devId);
#endif
    ret = NitroxTranslateResponseCode(ret);
    if (ret != 0) {
        return ret;
    }

    ato16((const byte*)&outSz, &outSz); 

    return outSz;
}


int NitroxRsaSSL_Sign(const byte* in, word32 inLen, byte* out,
                      word32 outLen, RsaKey* key)
{
    word32 ret;

    if (key == NULL || in == NULL || out == NULL || inLen == 0 || outLen <
                                                         (word32)key->n.used) {
        return BAD_FUNC_ARG;
    }

#ifdef HAVE_CAVIUM_V
    ret = CspPkcs1v15CrtEnc(key->asyncDev.dev.devId, CAVIUM_REQ_MODE, CAVIUM_SSL_GRP, CAVIUM_DPORT,
                            BT1, key->n.used, (word16)inLen,
                            key->q.dpraw, key->dQ.dpraw, key->p.dpraw, key->dP.dpraw, key->u.dpraw,
                            (byte*)in, out, &key->asyncDev.dev.reqId);
#else
    ret = CspPkcs1v15CrtEnc(CAVIUM_REQ_MODE, BT1, key->n.used, (word16)inLen,
                            key->q.dpraw, key->dQ.dpraw, key->p.dpraw, key->dP.dpraw, key->u.dpraw,
                            (byte*)in, out, &key->asyncDev.dev.reqId, key->asyncDev.dev.devId);
#endif
    ret = NitroxTranslateResponseCode(ret);
    if (ret != 0) {
        return ret;
    }

    return key->n.used;
}


int NitroxRsaSSL_Verify(const byte* in, word32 inLen, byte* out,
                        word32 outLen, RsaKey* key)
{
    word32 ret;
    word16 outSz = (word16)outLen;

    if (key == NULL || in == NULL || out == NULL || inLen != (word32)key->n.used) {
        return BAD_FUNC_ARG;
    }

#ifdef HAVE_CAVIUM_V
    ret = CspPkcs1v15Dec(key->asyncDev.dev.devId, CAVIUM_REQ_MODE, CAVIUM_SSL_GRP, CAVIUM_DPORT,
                         BT1, key->n.used, key->e.used,
                         key->n.dpraw, key->e.dpraw, (byte*)in, &outSz, out,
                         &key->asyncDev.dev.reqId);
#else
    ret = CspPkcs1v15Dec(CAVIUM_REQ_MODE, BT1, key->n.used, key->e.used,
                         key->n.dpraw, key->e.dpraw, (byte*)in, &outSz, out,
                         &key->asyncDev.dev.reqId, key->asyncDev.dev.devId);
#endif
    ret = NitroxTranslateResponseCode(ret);
    if (ret != 0) {
        return ret;
    }

    outSz = ntohs(outSz);

    return outSz;
}
#endif /* !NO_RSA */


#ifndef NO_AES
int NitroxAesSetKey(Aes* aes, const byte* key, word32 length, const byte* iv)
{
    if (aes == NULL)
        return BAD_FUNC_ARG;

    XMEMCPY(aes->key, key, length);   /* key still holds key, iv still in reg */
    if (length == 16)
        aes->type = AES_128_BIT;
    else if (length == 24)
        aes->type = AES_192_BIT;
    else if (length == 32)
        aes->type = AES_256_BIT;

    return wc_AesSetIV(aes, iv);
}

#ifdef HAVE_AES_CBC
int NitroxAesCbcEncrypt(Aes* aes, byte* out, const byte* in, word32 length)
{
    int ret;
    wolfssl_word offset = 0;

    while (length > WOLFSSL_MAX_16BIT) {
        word16 slen = (word16)WOLFSSL_MAX_16BIT;
    #ifdef HAVE_CAVIUM_V
        ret = CspEncryptAes(aes->asyncDev.dev.devId, CAVIUM_BLOCKING, DMA_DIRECT_DIRECT, 
                          CAVIUM_SSL_GRP, CAVIUM_DPORT, aes->asyncDev.dev.contextHandle,
                          FROM_DPTR, FROM_CTX, AES_CBC, aes->type, (byte*)aes->key,
                          (byte*)aes->reg, 0, NULL, slen, (byte*)in + offset,
                          out + offset, &aes->asyncDev.dev.reqId);
    #else
        ret = CspEncryptAes(CAVIUM_BLOCKING, aes->asyncDev.dev.contextHandle, CAVIUM_NO_UPDATE,
                          aes->type, slen, (byte*)in + offset, out + offset,
                          (byte*)aes->reg, (byte*)aes->key, &aes->asyncDev.dev.reqId,
                          aes->asyncDev.dev.devId);
    #endif
        ret = NitroxTranslateResponseCode(ret);
        if (ret != 0) {
            return ret;
        }
        length -= WOLFSSL_MAX_16BIT;
        offset += WOLFSSL_MAX_16BIT;
        XMEMCPY(aes->reg, out + offset - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    }
    if (length) {
        word16 slen = (word16)length;
    #ifdef HAVE_CAVIUM_V
        ret = CspEncryptAes(aes->asyncDev.dev.devId, CAVIUM_BLOCKING, DMA_DIRECT_DIRECT, 
                          CAVIUM_SSL_GRP, CAVIUM_DPORT, aes->asyncDev.dev.contextHandle,
                          FROM_DPTR, FROM_CTX, AES_CBC, aes->type, (byte*)aes->key,
                          (byte*)aes->reg,  0, NULL, slen, (byte*)in + offset,
                          out + offset, &aes->asyncDev.dev.reqId);
    #else
        ret = CspEncryptAes(CAVIUM_BLOCKING, aes->asyncDev.dev.contextHandle, CAVIUM_NO_UPDATE,
                          aes->type, slen, (byte*)in + offset, out + offset,
                          (byte*)aes->reg, (byte*)aes->key, &aes->asyncDev.dev.reqId,
                          aes->asyncDev.dev.devId);
    #endif
        ret = NitroxTranslateResponseCode(ret);
        if (ret != 0) {
            return ret;
        }
        XMEMCPY(aes->reg, out + offset+length - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    }
    return 0;
}

#ifdef HAVE_AES_DECRYPT
int NitroxAesCbcDecrypt(Aes* aes, byte* out, const byte* in, word32 length)
{
    wolfssl_word offset = 0;
    int ret;

    while (length > WOLFSSL_MAX_16BIT) {
        word16 slen = (word16)WOLFSSL_MAX_16BIT;
        XMEMCPY(aes->tmp, in + offset + slen - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    #ifdef HAVE_CAVIUM_V
        ret = CspDecryptAes(aes->asyncDev.dev.devId, CAVIUM_BLOCKING, DMA_DIRECT_DIRECT, 
                          CAVIUM_SSL_GRP, CAVIUM_DPORT, aes->asyncDev.dev.contextHandle,
                          FROM_DPTR, FROM_CTX, AES_CBC, aes->type, (byte*)aes->key, (byte*)aes->reg,
                          0, NULL, slen, (byte*)in + offset, out + offset, &aes->asyncDev.dev.reqId);
    #else
        ret = CspDecryptAes(CAVIUM_BLOCKING, aes->asyncDev.dev.contextHandle, CAVIUM_NO_UPDATE,
                          aes->type, slen, (byte*)in + offset, out + offset,
                          (byte*)aes->reg, (byte*)aes->key, &aes->asyncDev.dev.reqId,
                          aes->asyncDev.dev.devId);
    #endif
        ret = NitroxTranslateResponseCode(ret);
        if (ret != 0) {
            return ret;
        }
        length -= WOLFSSL_MAX_16BIT;
        offset += WOLFSSL_MAX_16BIT;
        XMEMCPY(aes->reg, aes->tmp, AES_BLOCK_SIZE);
    }
    if (length) {
        word16 slen = (word16)length;
        XMEMCPY(aes->tmp, in + offset + slen - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    #ifdef HAVE_CAVIUM_V
        ret = CspDecryptAes(aes->asyncDev.dev.devId, CAVIUM_BLOCKING, DMA_DIRECT_DIRECT, 
                          CAVIUM_SSL_GRP, CAVIUM_DPORT, aes->asyncDev.dev.contextHandle,
                          FROM_DPTR, FROM_CTX, AES_CBC, aes->type, (byte*)aes->key, (byte*)aes->reg,
                          0, NULL, slen, (byte*)in + offset, out + offset, &aes->asyncDev.dev.reqId);
    #else
        ret = CspDecryptAes(CAVIUM_BLOCKING, aes->asyncDev.dev.contextHandle, CAVIUM_NO_UPDATE,
                          aes->type, slen, (byte*)in + offset, out + offset,
                          (byte*)aes->reg, (byte*)aes->key, &aes->asyncDev.dev.reqId,
                          aes->asyncDev.dev.devId);
    #endif
        ret = NitroxTranslateResponseCode(ret);
        if (ret != 0) {
            return ret;
        }
        XMEMCPY(aes->reg, aes->tmp, AES_BLOCK_SIZE);
    }
    return 0;
}
#endif /* HAVE_AES_DECRYPT */
#endif /* HAVE_AES_CBC */
#endif /* !NO_AES */


#if !defined(NO_ARC4) && !defined(HAVE_CAVIUM_V)
void NitroxArc4SetKey(Arc4* arc4, const byte* key, word32 length)
{
    if (CspInitializeRc4(CAVIUM_BLOCKING, arc4->asyncDev.dev.contextHandle, length,
                         (byte*)key, &arc4->asyncDev.dev.reqId, arc4->devId) != 0) {
        WOLFSSL_MSG("Bad Cavium Arc4 Init");
    }
}

void NitroxArc4Process(Arc4* arc4, byte* out, const byte* in, word32 length)
{
    int ret;
    wolfssl_word offset = 0;

    while (length > WOLFSSL_MAX_16BIT) {
        word16 slen = (word16)WOLFSSL_MAX_16BIT;
        ret = CspEncryptRc4(CAVIUM_BLOCKING, arc4->asyncDev.dev.contextHandle,
            CAVIUM_UPDATE, slen, (byte*)in + offset, out + offset,
            &arc4->asyncDev.dev.reqId, arc4->devId);
        ret = NitroxTranslateResponseCode(ret);
        if (ret != 0) {
            return ret;
        }
        length -= WOLFSSL_MAX_16BIT;
        offset += WOLFSSL_MAX_16BIT;
    }
    if (length) {
        word16 slen = (word16)length;
        ret = CspEncryptRc4(CAVIUM_BLOCKING, arc4->asyncDev.dev.contextHandle,
            CAVIUM_UPDATE, slen, (byte*)in + offset, out + offset,
            &arc4->asyncDev.dev.reqId, arc4->devId);
        ret = NitroxTranslateResponseCode(ret);
        if (ret != 0) {
            return ret;
        }
    }
}
#endif /* !NO_ARC4 && !HAVE_CAVIUM_V */


#ifndef NO_DES3
int NitroxDes3SetKey(Des3* des3, const byte* key, const byte* iv)
{
    if (des3 == NULL)
        return BAD_FUNC_ARG;

    /* key[0] holds key, iv in reg */
    XMEMCPY(des3->key[0], key, DES_BLOCK_SIZE*3);

    return wc_Des3_SetIV(des3, iv);
}

int NitroxDes3CbcEncrypt(Des3* des3, byte* out, const byte* in, word32 length)
{
    wolfssl_word offset = 0;
    int ret;

    while (length > WOLFSSL_MAX_16BIT) {
        word16 slen = (word16)WOLFSSL_MAX_16BIT;
    #ifdef HAVE_CAVIUM_V
        ret = CspEncrypt3Des(des3->asyncDev.dev.devId, CAVIUM_BLOCKING, DMA_DIRECT_DIRECT,
                            CAVIUM_SSL_GRP, CAVIUM_DPORT, des3->asyncDev.dev.contextHandle,
                            FROM_DPTR, FROM_CTX, DES3_CBC, (byte*)des3->key[0],
                            (byte*)des3->reg, slen, (byte*)in + offset,
                            out + offset, &des3->asyncDev.dev.reqId);
    #else
        ret = CspEncrypt3Des(CAVIUM_BLOCKING, des3->asyncDev.dev.contextHandle,
                            CAVIUM_NO_UPDATE, slen, (byte*)in + offset,
                            out + offset, (byte*)des3->reg, (byte*)des3->key[0],
                            &des3->asyncDev.dev.reqId, des3->asyncDev.dev.devId);
    #endif
        ret = NitroxTranslateResponseCode(ret);
        if (ret != 0) {
            return ret;
        }
        length -= WOLFSSL_MAX_16BIT;
        offset += WOLFSSL_MAX_16BIT;
        XMEMCPY(des3->reg, out + offset - DES_BLOCK_SIZE, DES_BLOCK_SIZE);
    }
    if (length) {
        word16 slen = (word16)length;
    #ifdef HAVE_CAVIUM_V
        ret = CspEncrypt3Des(des3->asyncDev.dev.devId, CAVIUM_BLOCKING, DMA_DIRECT_DIRECT,
                            CAVIUM_SSL_GRP, CAVIUM_DPORT, des3->asyncDev.dev.contextHandle,
                            FROM_DPTR, FROM_CTX, DES3_CBC, (byte*)des3->key[0], (byte*)des3->reg,
                            slen, (byte*)in + offset, out + offset,
                            &des3->asyncDev.dev.reqId);
    #else
        ret = CspEncrypt3Des(CAVIUM_BLOCKING, des3->asyncDev.dev.contextHandle,
                            CAVIUM_NO_UPDATE, slen, (byte*)in + offset,
                            out + offset, (byte*)des3->reg, (byte*)des3->key[0],
                            &des3->asyncDev.dev.reqId, des3->asyncDev.dev.devId);
    #endif
        ret = NitroxTranslateResponseCode(ret);
        if (ret != 0) {
            return ret;
        }
        XMEMCPY(des3->reg, out+offset+length - DES_BLOCK_SIZE, DES_BLOCK_SIZE);
    }
    return 0;
}

int NitroxDes3CbcDecrypt(Des3* des3, byte* out, const byte* in, word32 length)
{
    wolfssl_word offset = 0;
    int ret;

    while (length > WOLFSSL_MAX_16BIT) {
        word16 slen = (word16)WOLFSSL_MAX_16BIT;
        XMEMCPY(des3->tmp, in + offset + slen - DES_BLOCK_SIZE, DES_BLOCK_SIZE);
    #ifdef HAVE_CAVIUM_V
        ret = CspDecrypt3Des(des3->asyncDev.dev.devId, CAVIUM_BLOCKING, DMA_DIRECT_DIRECT,
                            CAVIUM_SSL_GRP, CAVIUM_DPORT, des3->asyncDev.dev.contextHandle,
                            FROM_DPTR, FROM_CTX, DES3_CBC, (byte*)des3->key[0], (byte*)des3->reg,
                            slen, (byte*)in + offset, out + offset,
                            &des3->asyncDev.dev.reqId);
    #else
        ret = CspDecrypt3Des(CAVIUM_BLOCKING, des3->asyncDev.dev.contextHandle,
                           CAVIUM_NO_UPDATE, slen, (byte*)in + offset, out + offset,
                           (byte*)des3->reg, (byte*)des3->key[0], &des3->asyncDev.dev.reqId,
                           des3->asyncDev.dev.devId);
    #endif
        ret = NitroxTranslateResponseCode(ret);
        if (ret != 0) {
            return ret;
        }
        length -= WOLFSSL_MAX_16BIT;
        offset += WOLFSSL_MAX_16BIT;
        XMEMCPY(des3->reg, des3->tmp, DES_BLOCK_SIZE);
    }
    if (length) {
        word16 slen = (word16)length;
        XMEMCPY(des3->tmp, in + offset + slen - DES_BLOCK_SIZE,DES_BLOCK_SIZE);
    #ifdef HAVE_CAVIUM_V
        ret = CspDecrypt3Des(des3->asyncDev.dev.devId, CAVIUM_BLOCKING, DMA_DIRECT_DIRECT,
                            CAVIUM_SSL_GRP, CAVIUM_DPORT, des3->asyncDev.dev.contextHandle,
                            FROM_DPTR, FROM_CTX, DES3_CBC, (byte*)des3->key[0], (byte*)des3->reg,
                            slen, (byte*)in + offset, out + offset,
                            &des3->asyncDev.dev.reqId);
    #else
        ret = CspDecrypt3Des(CAVIUM_BLOCKING, des3->asyncDev.dev.contextHandle,
                           CAVIUM_NO_UPDATE, slen, (byte*)in + offset, out + offset,
                           (byte*)des3->reg, (byte*)des3->key[0], &des3->asyncDev.dev.reqId,
                           des3->asyncDev.dev.devId);
    #endif
        ret = NitroxTranslateResponseCode(ret);
        if (ret != 0) {
            return ret;
        }
        XMEMCPY(des3->reg, des3->tmp, DES_BLOCK_SIZE);
    }
    return 0;
}
#endif /* !NO_DES3 */


#ifndef NO_HMAC
int NitroxHmacFinal(Hmac* hmac, byte* hash)
{
    int ret = -1;

#ifdef HAVE_CAVIUM_V
    word16 hashLen = wc_HmacSizeByType(hmac->macType);
    ret = CspHmac(hmac->asyncDev.dev.devId, CAVIUM_BLOCKING, DMA_DIRECT_DIRECT,
                  CAVIUM_SSL_GRP, CAVIUM_DPORT, hmac->type, hmac->keyLen,
                  (byte*)hmac->ipad, hmac->dataLen, hmac->data, hashLen,
                  hash, &hmac->asyncDev.dev.reqId);
#else
    ret = CspHmac(CAVIUM_BLOCKING, hmac->type, NULL, hmac->keyLen,
                  (byte*)hmac->ipad, hmac->dataLen, hmac->data, hash,
                  &hmac->asyncDev.dev.reqId, hmac->asyncDev.dev.devId);
#endif
    ret = NitroxTranslateResponseCode(ret);
    if (ret != 0) {
        return ret;
    }

    hmac->innerHashKeyed = 0;  /* tell update to start over if used again */

    return 0;
}

int NitroxHmacUpdate(Hmac* hmac, const byte* msg, word32 length)
{
    word16 add = (word16)length;
    word32 total;
    byte*  tmp;

    if (length > WOLFSSL_MAX_16BIT) {
        WOLFSSL_MSG("Too big msg for cavium hmac");
        return -1;
    }

    if (hmac->innerHashKeyed == 0) {  /* starting new */
        hmac->dataLen        = 0;
        hmac->innerHashKeyed = 1;
    }

    total = add + hmac->dataLen;
    if (total > WOLFSSL_MAX_16BIT) {
        WOLFSSL_MSG("Too big msg for cavium hmac");
        return -1;
    }

    tmp = XMALLOC(hmac->dataLen + add, NULL, DYNAMIC_TYPE_ASYNC_TMP);
    if (tmp == NULL) {
        WOLFSSL_MSG("Out of memory for cavium update");
        return -1;
    }
    if (hmac->dataLen)
        XMEMCPY(tmp, hmac->data,  hmac->dataLen);
    XMEMCPY(tmp + hmac->dataLen, msg, add);

    hmac->dataLen += add;
    XFREE(hmac->data, NULL, DYNAMIC_TYPE_ASYNC_TMP);
    hmac->data = tmp;

    return 0;
}

int NitroxHmacSetKey(Hmac* hmac, int type, const byte* key, word32 length)
{
    hmac->macType = (byte)type;
    
    /* Determine Cavium HashType */
    switch(type) {
    #ifndef NO_MD5
        case MD5:
            hmac->type = MD5_TYPE;
            break;
    #endif
    #ifndef NO_SHA
        case SHA:
            hmac->type = SHA1_TYPE;
            break;
    #endif
    #ifndef NO_SHA256
        case SHA256:
        #ifdef HAVE_CAVIUM_V
            hmac->type = SHA2_SHA256;
        #else
            hmac->type = SHA256_TYPE;
        #endif
            break;
    #endif
    #ifdef HAVE_CAVIUM_V
        #ifndef WOLFSSL_SHA512
            case SHA512:
                hmac->type = SHA2_SHA512;
                break;
        #endif
        #ifndef WOLFSSL_SHA384
            case SHA384:
                hmac->type = SHA2_SHA384;
                break;
        #endif
    #endif /* HAVE_CAVIUM_V */
        default:
            WOLFSSL_MSG("unsupported cavium hmac type");
            break;
    }

    hmac->innerHashKeyed = 0;  /* should we key Startup flag */

    hmac->keyLen = (word16)length;
    /* store key in ipad */
    XMEMCPY(hmac->ipad, key, length);

    return 0;
}
#endif /* !NO_HMAC */


#if !defined(HAVE_HASHDRBG) && !defined(NO_RC4)
void NitroxRngGenerateBlock(WC_RNG* rng, byte* output, word32 sz)
{
    wolfssl_word offset = 0;
    word32      requestId;

    while (sz > WOLFSSL_MAX_16BIT) {
        word16 slen = (word16)WOLFSSL_MAX_16BIT;
    #ifdef HAVE_CAVIUM_V
        ret = CspTrueRandom(rng->asyncDev.dev.devId, CAVIUM_BLOCKING, DMA_DIRECT_DIRECT, 
                            CAVIUM_SSL_GRP, CAVIUM_DPORT, slen, output + offset, &requestId);
    #else
        ret = CspRandom(CAVIUM_BLOCKING, slen, output + offset, &requestId,
                        rng->asyncDev.dev.devId);
    #endif
        ret = NitroxTranslateResponseCode(ret);
        if (ret != 0) {
            return ret;
        }
        sz     -= WOLFSSL_MAX_16BIT;
        offset += WOLFSSL_MAX_16BIT;
    }
    if (sz) {
        word16 slen = (word16)sz;
    #ifdef HAVE_CAVIUM_V
        ret = CspTrueRandom(rng->asyncDev.dev.devId, CAVIUM_BLOCKING, DMA_DIRECT_DIRECT, 
                            CAVIUM_SSL_GRP, CAVIUM_DPORT, slen, output + offset, &requestId);
    #else
        ret = CspRandom(CAVIUM_BLOCKING, slen, output + offset, &requestId,
                        rng->asyncDev.dev.devId);
    #endif
        ret = NitroxTranslateResponseCode(ret);
        if (ret != 0) {
            return ret;
        }
    }
}
#endif /* !defined(HAVE_HASHDRBG) && !defined(NO_RC4) */


#endif /* WOLFSSL_ASYNC_CRYPT */

#endif /* HAVE_CAVIUM */
