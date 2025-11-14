/* cavium_nitrox.c
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
#ifdef HAVE_ECC
    #include <wolfssl/wolfcrypt/ecc.h>
#endif
#include <wolfssl/wolfcrypt/hmac.h>

#include <wolfssl/wolfcrypt/port/cavium/cavium_nitrox.h>
#ifndef HAVE_CAVIUM_V
    #include "cavium_ioctl.h"
#else
    #include "cavium_sym_crypto.h"
    #include "cavium_asym_crypto.h"
#endif
#include <errno.h>
#include <netinet/in.h> /* For ntohs */

static CspHandle mLastDevHandle = INVALID_DEVID;

#ifndef NITROX_MAX_BUF_LEN
    /* max buffer pool size is 32768, but need to leave room for request */
    #define NITROX_MAX_BUF_LEN (32768U / 2)
#endif

int NitroxTranslateResponseCode(int ret)
{
    switch (ret) {
        case EAGAIN:
        case ERR_REQ_PENDING:
        case REQUEST_PENDING:
            ret = WC_PENDING_E;
            break;
        case ERR_REQ_TIMEOUT:
            ret = WC_TIMEOUT_E;
            break;
        case ERR_DATA_LEN_INVALID:
            ret = BAD_FUNC_ARG;
            break;
        case ERR_ECC_SIGNATURE_MISMATCH:
            ret = SIG_VERIFY_E;
            break;
        case ERR_PKCS_DECRYPT_INCORRECT:
            ret = ASN_SIG_CONFIRM_E; /* RSA_PAD_E */
            break;
        case ERR_GC_ICV_MISCOMPARE:
            ret = AES_GCM_AUTH_E;
            break;
        case 0:
        case 1:
            ret = 0; /* treat as success */
            break;
        default:
            printf("NitroxTranslateResponseCode Unknown ret=0x%x\n", ret);
            ret = ASYNC_INIT_E;
    }
    return ret;
}

static WC_INLINE void NitroxDevClear(WC_ASYNC_DEV* dev)
{
    /* values that must be reset prior to calling algo */
    /* this is because operation may complete before added to event list */
    dev->event.ret = WC_PENDING_E;
    dev->event.state = WOLF_EVENT_STATE_PENDING;
    dev->event.reqId = 0;
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

CspHandle NitroxOpenDeviceDefault(void)
{
    return NitroxOpenDevice(CAVIUM_DIRECT, CAVIUM_DEV_ID);
}


int NitroxAllocContext(WC_ASYNC_DEV* dev, CspHandle devId,
    context_type_t type)
{
    int ret;

    if (dev == NULL) {
        return -1;
    }

    /* If invalid handle provided, use last open one */
    if (devId == INVALID_DEVID) {
        devId = NitroxGetDeviceHandle();
    }

#ifdef HAVE_CAVIUM_V
    ret = CspAllocContext(devId, type, &dev->nitrox.contextHandle);
#else
    ret = CspAllocContext(type, &dev->nitrox.contextHandle, devId);
#endif
    if (ret != 0) {
        return -1;
    }

    dev->nitrox.type = type;
    dev->nitrox.devId = devId;

    return 0;
}

void NitroxFreeContext(WC_ASYNC_DEV* dev)
{
    if (dev == NULL) {
        return;
    }

#ifdef HAVE_CAVIUM_V
    CspFreeContext(dev->nitrox.devId, dev->nitrox.type,
        dev->nitrox.contextHandle);
#else
    CspFreeContext(dev->nitrox.type, dev->nitrox.contextHandle,
        dev->nitrox.devId);
#endif
}

void NitroxCloseDevice(CspHandle devId)
{
    if (devId >= 0) {
        CspShutdown(devId);
    }
}

#if defined(WOLFSSL_ASYNC_CRYPT)

int NitroxCheckRequest(WC_ASYNC_DEV* dev, WOLF_EVENT* event)
{
    int ret = BAD_FUNC_ARG;
    if (dev && event) {
        ret = CspCheckForCompletion(dev->nitrox.devId, event->reqId);
        event->ret = NitroxTranslateResponseCode(ret);
    }
    return ret;
}

int NitroxCheckRequests(WC_ASYNC_DEV* dev,
    CspMultiRequestStatusBuffer* req_stat_buf)
{
    int ret;

    if (dev == NULL || req_stat_buf == NULL)
        return BAD_FUNC_ARG;

#ifdef HAVE_CAVIUM_V
    ret = CspGetAllResults(req_stat_buf, dev->nitrox.devId);
#else
    word32 res_count = 0;
    word32 buf_size = sizeof(req_stat_buf->req);
    ret = CspGetAllResults(req_stat_buf->req, buf_size, &res_count,
        dev->nitrox.devId);
    multi_req->count = res_count;
#endif

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

    /* init return codes */
    NitroxDevClear(&key->asyncDev);

#ifdef HAVE_CAVIUM_V
    ret = CspMe(key->asyncDev.nitrox.devId, CAVIUM_REQ_MODE, CAVIUM_SSL_GRP,
            CAVIUM_DPORT, modLen, expLen, inLen, modulus, exponent, (Uint8*)in,
            out, &key->asyncDev.nitrox.reqId);
    #if 0
    /* TODO: Try MeCRT */
    ret = CspMeCRT();
    #endif
#else
    /* Not implemented/supported */
    ret = NOT_COMPILED_IN;
#endif

#ifdef WOLFSSL_NITROX_DEBUG
    printf("NitroxRsaExptMod: ret %x, req %lx in %p (%d), out %p (%d)\n",
        ret, key->asyncDev.nitrox.reqId, in, inLen, out, *outLen);
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
    int ret;

    if (key == NULL || in == NULL || out == NULL ||
                                            outLen < (word32)key->n.raw.len) {
        return BAD_FUNC_ARG;
    }

    /* init return codes */
    NitroxDevClear(&key->asyncDev);

#ifdef HAVE_CAVIUM_V
    ret = CspPkcs1v15Enc(key->asyncDev.nitrox.devId, CAVIUM_REQ_MODE,
        CAVIUM_SSL_GRP, CAVIUM_DPORT, BT2, key->n.raw.len, key->e.raw.len,
        (word16)inLen, key->n.raw.buf, key->e.raw.buf, (byte*)in, out,
        &key->asyncDev.nitrox.reqId);
#else
    ret = CspPkcs1v15Enc(CAVIUM_REQ_MODE, BT2, key->n.raw.len, key->e.raw.len,
        (word16)inLen, key->n.raw.buf, key->e.raw.buf, (byte*)in, out,
        &key->asyncDev.nitrox.reqId, key->asyncDev.nitrox.devId);
#endif

#ifdef WOLFSSL_NITROX_DEBUG
    printf("NitroxRsaPublicEncrypt: ret %x, req %lx in %p (%d), out %p (%d)\n",
        ret, key->asyncDev.nitrox.reqId, in, inLen, out, outLen);
#endif

    ret = NitroxTranslateResponseCode(ret);
    if (ret != 0) {
        return ret;
    }

    return key->n.raw.len;
}


int NitroxRsaPrivateDecrypt(const byte* in, word32 inLen, byte* out,
                            word32* outLen, RsaKey* key)
{
    int ret;

    if (key == NULL || in == NULL || out == NULL ||
                                            inLen != (word32)key->n.raw.len) {
        return BAD_FUNC_ARG;
    }

    /* init return codes */
    NitroxDevClear(&key->asyncDev);

#ifdef HAVE_CAVIUM_V
    ret = CspPkcs1v15CrtDec(key->asyncDev.nitrox.devId, CAVIUM_REQ_MODE,
        CAVIUM_SSL_GRP, CAVIUM_DPORT, BT2, key->n.raw.len, key->q.raw.buf,
        key->dQ.raw.buf, key->p.raw.buf, key->dP.raw.buf, key->u.raw.buf,
        (byte*)in, (Uint16*)outLen, out, &key->asyncDev.nitrox.reqId);
#else
    ret = CspPkcs1v15CrtDec(CAVIUM_REQ_MODE, BT2, key->n.raw.len,
        key->q.raw.buf, key->dQ.raw.buf, key->p.raw.buf, key->dP.raw.buf,
        key->u.raw.buf, (byte*)in, &outLen, out, &key->asyncDev.nitrox.reqId,
        key->asyncDev.nitrox.devId);
#endif

#ifdef WOLFSSL_NITROX_DEBUG
    printf("NitroxRsaPrivateDecrypt: ret %x, req %lx in %p (%d), out %p (%d)\n",
        ret, key->asyncDev.nitrox.reqId, in, inLen, out, *outLen);
#endif

    ret = NitroxTranslateResponseCode(ret);
    if (ret != 0) {
        return ret;
    }

    *outLen = ntohs(*outLen);

    return *outLen;
}


int NitroxRsaSSL_Sign(const byte* in, word32 inLen, byte* out,
                      word32 outLen, RsaKey* key)
{
    int ret;

    if (key == NULL || in == NULL || out == NULL || inLen == 0 || outLen <
                                                     (word32)key->n.raw.len) {
        return BAD_FUNC_ARG;
    }

    /* init return codes */
    NitroxDevClear(&key->asyncDev);

#ifdef HAVE_CAVIUM_V
    ret = CspPkcs1v15CrtEnc(key->asyncDev.nitrox.devId, CAVIUM_REQ_MODE,
        CAVIUM_SSL_GRP, CAVIUM_DPORT, BT1, key->n.raw.len, (word16)inLen,
        key->q.raw.buf, key->dQ.raw.buf, key->p.raw.buf, key->dP.raw.buf,
        key->u.raw.buf, (byte*)in, out, &key->asyncDev.nitrox.reqId);
#else
    ret = CspPkcs1v15CrtEnc(CAVIUM_REQ_MODE, BT1, key->n.raw.len, (word16)inLen,
        key->q.raw.buf, key->dQ.raw.buf, key->p.raw.buf, key->dP.raw.buf,
        key->u.raw.buf, (byte*)in, out, &key->asyncDev.nitrox.reqId,
        key->asyncDev.nitrox.devId);
#endif

#ifdef WOLFSSL_NITROX_DEBUG
    printf("NitroxRsaSSL_Sign: ret %x, req %lx in %p (%d), out %p (%d)\n",
        ret, key->asyncDev.nitrox.reqId, in, inLen, out, outLen);
#endif

    ret = NitroxTranslateResponseCode(ret);
    if (ret != 0) {
        return ret;
    }

    return key->n.raw.len;
}


int NitroxRsaSSL_Verify(const byte* in, word32 inLen, byte* out,
                        word32* outLen, RsaKey* key)
{
    int ret;

    if (key == NULL || in == NULL || out == NULL ||
                                            inLen != (word32)key->n.raw.len) {
        return BAD_FUNC_ARG;
    }

    /* init return codes */
    NitroxDevClear(&key->asyncDev);

#ifdef HAVE_CAVIUM_V
    ret = CspPkcs1v15Dec(key->asyncDev.nitrox.devId, CAVIUM_REQ_MODE,
        CAVIUM_SSL_GRP, CAVIUM_DPORT, BT1, key->n.raw.len, key->e.raw.len,
        key->n.raw.buf, key->e.raw.buf, (byte*)in, (Uint16*)outLen, out,
        &key->asyncDev.nitrox.reqId);
#else
    ret = CspPkcs1v15Dec(CAVIUM_REQ_MODE, BT1, key->n.raw.len, key->e.raw.len,
        key->n.raw.buf, key->e.raw.buf, (byte*)in, &outLen, out,
        &key->asyncDev.nitrox.reqId, key->asyncDev.nitrox.devId);
#endif

#ifdef WOLFSSL_NITROX_DEBUG
    printf("NitroxRsaSSL_Verify: ret %x, req %lx in %p (%d), out %p (%d)\n",
        ret, key->asyncDev.nitrox.reqId, in, inLen, out, *outLen);
#endif

    ret = NitroxTranslateResponseCode(ret);
    if (ret != 0) {
        return ret;
    }

    *outLen = ntohs(*outLen);

    return *outLen;
}
#endif /* !NO_RSA */



#if defined(HAVE_ECC) && defined(HAVE_CAVIUM_V)


static int NitroxEccGetCid(ecc_key* key, CurveId* cid)
{
    int ret = 0;

    if (key == NULL || key->dp == NULL)
        return BAD_FUNC_ARG;

    switch (key->dp->id) {
    #if 0 /* ECDH P521 appears to be broken on Nitrox V v1.4 SDK */
        case ECC_SECP521R1:
            *cid = P521;
            break;
    #endif
        case ECC_SECP384R1:
            *cid = P384;
            break;
        case ECC_SECP256R1:
            *cid = P256;
            break;
        case ECC_SECP224R1:
            *cid = P224;
            break;
        case ECC_SECP192R1:
            *cid = P192;
            break;
        default:
            ret = BAD_FUNC_ARG;
            break;
    }

    return ret;
}
int NitroxEccIsCurveSupported(ecc_key* key)
{
    CurveId cid;
    return NitroxEccGetCid(key, &cid) == 0 ? 1 : 0;
}

int NitroxEccGetSize(ecc_key* key)
{
    return ROUNDUP8(key->dp->size);
}

int NitroxEccPad(WC_BIGINT* bi, word32 padTo)
{
    if (bi->len < padTo) {
        int x = padTo - bi->len;
        XMEMCPY(bi->buf + x, bi->buf, bi->len);
        XMEMSET(bi->buf, 0, x);
        bi->len = padTo;
    }
    return 0;
}

int NitroxEccRsSplit(ecc_key* key, WC_BIGINT* r, WC_BIGINT* s)
{
    if (NitroxEccIsCurveSupported(key)) {
        int rSz = NitroxEccGetSize(key);

        /* split r and s */
        XMEMCPY(s->buf, r->buf + rSz, key->dp->size);
        XMEMSET(r->buf + key->dp->size, 0, key->dp->size);
        r->len = key->dp->size;
        s->len = key->dp->size;
    }
    return 0;
}

#ifdef HAVE_ECC_DHE
int NitroxEcdh(ecc_key* key,
    WC_BIGINT* k, WC_BIGINT* xG, WC_BIGINT* yG,
    byte* out, word32* outlen, WC_BIGINT* q)
{
    int ret;
    CurveId cid;
    word32 curveSz;

    ret = NitroxEccGetCid(key, &cid);
    if (ret < 0)
        return ret;

    /* out buffer requires spaces for X and Y even though only X is used */
    curveSz = NitroxEccGetSize(key);
    if (*outlen < curveSz * 2)
        return BUFFER_E;

    /* init return codes */
    NitroxDevClear(&key->asyncDev);

    ret = CspECPointMul(key->asyncDev.nitrox.devId, CAVIUM_REQ_MODE,
        CAVIUM_SSL_GRP, CAVIUM_DPORT, cid,
        xG->buf, yG->buf, q->buf, k->len, k->buf, out, out + curveSz,
        &key->asyncDev.nitrox.reqId);

#ifdef WOLFSSL_NITROX_DEBUG
    printf("NitroxEcdh: ret %x, req %lx out %p (%d)\n",
        ret, key->asyncDev.nitrox.reqId, out, *outlen);
#endif

    ret = NitroxTranslateResponseCode(ret);
    if (ret != 0) {
        return ret;
    }

    return ret;
}
#endif /* HAVE_ECC_DHE */

#ifdef HAVE_ECC_SIGN
int NitroxEcdsaSign(ecc_key* key,
    WC_BIGINT* m, WC_BIGINT* d, WC_BIGINT* k,
    WC_BIGINT* r, WC_BIGINT* s, WC_BIGINT* q, WC_BIGINT* n)
{
    int ret;
    CurveId cid;

    ret = NitroxEccGetCid(key, &cid);
    if (ret < 0)
        return ret;

    /* init return codes */
    NitroxDevClear(&key->asyncDev);

    (void)s; /* placed at end of R */

    ret = CspECDSASign(key->asyncDev.nitrox.devId, CAVIUM_REQ_MODE,
        CAVIUM_SSL_GRP, CAVIUM_DPORT, cid, q->buf, n->buf, k->len, k->buf,
        m->len, m->buf, d->buf, r->buf, &key->asyncDev.nitrox.reqId);

#ifdef WOLFSSL_NITROX_DEBUG
    printf("NitroxEcdsaSign: ret %x, req %lx msg %p (%d), r %p\n",
        ret, key->asyncDev.nitrox.reqId, m->buf, m->len, r->buf);
#endif

    ret = NitroxTranslateResponseCode(ret);
    if (ret != 0) {
        return ret;
    }

    return ret;
}
#endif /* HAVE_ECC_SIGN */

#ifdef HAVE_ECC_VERIFY
int NitroxEcdsaVerify(ecc_key* key,
        WC_BIGINT* m, WC_BIGINT* xp, WC_BIGINT* yp,
        WC_BIGINT* r, WC_BIGINT* s,
        WC_BIGINT* q, WC_BIGINT* n, int* stat)
{
    int ret;
    CurveId cid;
    int curveSz = key->dp->size;

    ret = NitroxEccGetCid(key, &cid);
    if (ret < 0)
        return ret;

    /* init return codes */
    NitroxDevClear(&key->asyncDev);

    /* adjust r and s for leading zero pad */
    NitroxEccPad(r, curveSz);
    NitroxEccPad(s, curveSz);

    ret = CspECDSAVerify(key->asyncDev.nitrox.devId, CAVIUM_REQ_MODE,
        CAVIUM_SSL_GRP, CAVIUM_DPORT, cid, r->buf, s->buf, m->len, m->buf,
        n->buf, q->buf, xp->buf, yp->buf, &key->asyncDev.nitrox.reqId);

    /* hardware will ret failure if verify fails */
    *stat = 1;

#ifdef WOLFSSL_NITROX_DEBUG
    printf("NitroxEcdsaVerify: ret %x, req %lx msg %p (%d), r %p, s%p\n",
        ret, key->asyncDev.nitrox.reqId, m->buf, m->len, r->buf, s->buf);
#endif

    ret = NitroxTranslateResponseCode(ret);
    if (ret != 0) {
        return ret;
    }

    return ret;
}
#endif /* HAVE_ECC_VERIFY */
#endif /* HAVE_ECC */


#ifndef NO_AES

#if defined(HAVE_AES_CBC) || defined(HAVE_AESGCM)

static int NitroxAesGetType(Aes* aes, AesType* type)
{
    int ret = 0;
    switch (aes->keylen) {
        case 16:
            *type = AES_128_BIT;
            break;
        case 24:
            *type = AES_192_BIT;
            break;
        case 32:
            *type = AES_256_BIT;
            break;
        default:
            ret = BAD_FUNC_ARG;
            break;
    }
    return ret;
}

static int NitroxAesEncrypt(Aes* aes, int aes_algo,
    const byte* key, const byte* iv,
    byte* out, const byte* in, word32 length,
    word32 aad_len, const byte* aad, byte* tag)
{
    int ret = 0, cav_ret = 0;
    int offset = 0;
    AesType aes_type;
    const int blockMode = CAVIUM_BLOCKING;

    ret = NitroxAesGetType(aes, &aes_type);
    if (ret != 0) {
        return ret;
    }

    /* init return codes */
    if (blockMode == CAVIUM_REQ_MODE)
        NitroxDevClear(&aes->asyncDev);

    while (length > 0) {
        word32 slen = length;
        if (slen > NITROX_MAX_BUF_LEN)
            slen = NITROX_MAX_BUF_LEN;

    #ifdef HAVE_CAVIUM_V
        cav_ret = CspEncryptAes(aes->asyncDev.nitrox.devId, blockMode,
            DMA_DIRECT_DIRECT, CAVIUM_SSL_GRP, CAVIUM_DPORT,
            aes->asyncDev.nitrox.contextHandle, FROM_DPTR, FROM_CTX, aes_algo,
            aes_type, (byte*)key, (byte*)iv, aad_len, (byte*)aad, (byte*)tag,
            (word16)slen, (byte*)in + offset, out + offset,
            &aes->asyncDev.nitrox.reqId);
    #else
        if (aes_type != AES_CBC) {
            ret = NOT_COMPILED_IN;
            break;
        }

        (void)aad_len;
        (void)aad;
        (void)tag;

        cav_ret = CspEncryptAes(blockMode, aes->asyncDev.nitrox.contextHandle,
            CAVIUM_NO_UPDATE, aes_type,
            (word16)slen, (byte*)in + offset, out + offset,
            (byte*)iv, (byte*)key,
            &aes->asyncDev.nitrox.reqId, aes->asyncDev.nitrox.devId);
    #endif
        ret = NitroxTranslateResponseCode(cav_ret);
        if (ret != 0) {
            break;
        }

        length -= slen;
        offset += slen;

        XMEMCPY(aes->reg, out + offset - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    }

#ifdef WOLFSSL_NITROX_DEBUG
    printf("NitroxAesEncrypt: ret %x (%d), algo %d, in %p, out %p, sz %d, "
           "iv %p, aad %p (%d), tag %p\n",
        cav_ret, ret, aes_algo, in, out, offset, iv, aad, aad_len, tag);
#endif

    return ret;
}

#ifdef HAVE_AES_DECRYPT
static int NitroxAesDecrypt(Aes* aes, int aes_algo,
    const byte* key, const byte* iv,
    byte* out, const byte* in, word32 length,
    word32 aad_len, const byte* aad, const byte* tag)
{
    int ret = 0, cav_ret = 0;
    int offset = 0;
    AesType aes_type;
    const int blockMode = CAVIUM_BLOCKING;

    ret = NitroxAesGetType(aes, &aes_type);
    if (ret != 0) {
        return ret;
    }

    /* init return codes */
    if (blockMode == CAVIUM_REQ_MODE)
        NitroxDevClear(&aes->asyncDev);

    while (length > 0) {
        word32 slen = length;
        if (slen > NITROX_MAX_BUF_LEN)
            slen = NITROX_MAX_BUF_LEN;

        XMEMCPY(aes->tmp, in + offset + slen - AES_BLOCK_SIZE, AES_BLOCK_SIZE);

    #ifdef HAVE_CAVIUM_V
        cav_ret = CspDecryptAes(aes->asyncDev.nitrox.devId, blockMode,
            DMA_DIRECT_DIRECT, CAVIUM_SSL_GRP, CAVIUM_DPORT,
            aes->asyncDev.nitrox.contextHandle, FROM_DPTR, FROM_CTX, aes_algo,
            aes_type, (byte*)key, (byte*)iv, aad_len, (byte*)aad, (byte*)tag,
            (word16)slen, (byte*)in + offset, out + offset,
            &aes->asyncDev.nitrox.reqId);
    #else
        if (aes_type != AES_CBC) {
            ret = NOT_COMPILED_IN;
            break;
        }

        (void)aad_len;
        (void)aad;
        (void)tag;

        cav_ret = CspDecryptAes(blockMode, aes->asyncDev.nitrox.contextHandle,
            CAVIUM_NO_UPDATE, aes_sz_type, (word16)slen, (byte*)in + offset,
            out + offset, (byte*)iv, (byte*)key,
            &aes->asyncDev.nitrox.reqId, aes->asyncDev.nitrox.devId);
    #endif
        ret = NitroxTranslateResponseCode(cav_ret);
        if (ret != 0) {
            break;
        }
        length -= slen;
        offset += slen;

        XMEMCPY(aes->reg, aes->tmp, AES_BLOCK_SIZE);
    }

#ifdef WOLFSSL_NITROX_DEBUG
    printf("NitroxAesDecrypt: ret %x (%d), algo %d, in %p, out %p, sz %d, "
           "iv %p, aad %p (%d), tag %p\n",
        cav_ret, ret, aes_algo, in, out, offset, iv, aad, aad_len, tag);
#endif

    return ret;
}
#endif /* HAVE_AES_DECRYPT */

#ifdef HAVE_AES_CBC
int NitroxAesCbcEncrypt(Aes* aes, byte* out, const byte* in, word32 length)
{
    return NitroxAesEncrypt(aes, AES_CBC,
        (byte*)aes->devKey, (byte*)aes->reg,
        out, in, length, 0, NULL, NULL);
}

#ifdef HAVE_AES_DECRYPT
int NitroxAesCbcDecrypt(Aes* aes, byte* out, const byte* in, word32 length)
{
    return NitroxAesDecrypt(aes, AES_CBC,
        (byte*)aes->devKey, (byte*)aes->reg,
        out, in, length, 0, NULL, NULL);
}
#endif /* HAVE_AES_DECRYPT */
#endif /* HAVE_AES_CBC */

#ifdef HAVE_AESGCM
int NitroxAesGcmEncrypt(Aes* aes,
    byte* out, const byte* in, word32 sz,
    const byte* key, word32 keySz,
    const byte* iv, word32 ivSz,
    byte* authTag, word32 authTagSz,
    const byte* authIn, word32 authInSz)
{
    const byte* ivTmp = iv;
    byte ivLcl[AES_BLOCK_SIZE];

    (void)keySz;
    (void)authTagSz;

    /* Nitrox HW requires IV buffer to be 16-bytes */
    if (ivSz < AES_BLOCK_SIZE) {
        ivTmp = ivLcl;
        XMEMCPY(ivLcl, iv, ivSz);
    }

    return NitroxAesEncrypt(aes, AES_GCM, key, ivTmp, out, in, sz,
        authInSz, authIn, authTag);
}

#ifdef HAVE_AES_DECRYPT
int NitroxAesGcmDecrypt(Aes* aes,
    byte* out, const byte* in, word32 sz,
    const byte* key, word32 keySz,
    const byte* iv, word32 ivSz,
    const byte* authTag, word32 authTagSz,
    const byte* authIn, word32 authInSz)
{
    const byte* ivTmp = iv;
    byte ivLcl[AES_BLOCK_SIZE];

    (void)keySz;
    (void)authTagSz;

    /* Nitrox HW requires IV buffer to be 16-bytes */
    if (ivSz < AES_BLOCK_SIZE) {
        ivTmp = ivLcl;
        XMEMCPY(ivLcl, iv, ivSz);
    }

    return NitroxAesDecrypt(aes, AES_GCM, key, ivTmp, out, in, sz,
        authInSz, authIn, authTag);
}
#endif /* HAVE_AES_DECRYPT */
#endif /* HAVE_AESGCM */

#endif /* HAVE_AES_CBC || HAVE_AESGCM */
#endif /* !NO_AES */


#if !defined(NO_RC4) && !defined(HAVE_CAVIUM_V)
int NitroxArc4SetKey(Arc4* arc4, const byte* key, word32 length)
{
    if (CspInitializeRc4(CAVIUM_BLOCKING, arc4->asyncDev.nitrox.contextHandle,
          length, (byte*)key, &arc4->asyncDev.nitrox.reqId, arc4->devId) != 0) {
        WOLFSSL_MSG("Bad Cavium Arc4 Init");
        return ASYNC_INIT_E;
    }
    return 0;
}

int NitroxArc4Process(Arc4* arc4, byte* out, const byte* in, word32 length)
{
    int ret = 0, cav_ret = 0;
    int offset = 0;
    const int blockMode = CAVIUM_BLOCKING;

    /* init return codes */
    if (blockMode == CAVIUM_REQ_MODE)
        NitroxDevClear(&arc4->asyncDev);

    while (length > 0) {
        word32 slen = length;
        if (slen > NITROX_MAX_BUF_LEN)
            slen = NITROX_MAX_BUF_LEN;

        cav_ret = CspEncryptRc4(blockMode,
            arc4->asyncDev.nitrox.contextHandle, CAVIUM_UPDATE, (word16)slen,
            (byte*)in + offset, out + offset,
            &arc4->asyncDev.nitrox.reqId, arc4->devId);
        ret = NitroxTranslateResponseCode(cav_ret);
        if (ret != 0) {
            break;
        }

        length -= slen;
        offset += slen;
    }

#ifdef WOLFSSL_NITROX_DEBUG
    printf("NitroxArc4Process: ret %x (%d), in %p, output %p, sz %d\n",
        cav_ret, ret, in, output, offset);
#endif

    return ret;
}
#endif /* !NO_RC4 && !HAVE_CAVIUM_V */


#ifndef NO_DES3
int NitroxDes3CbcEncrypt(Des3* des3, byte* out, const byte* in, word32 length)
{
    int ret = 0, cav_ret = 0;
    int offset = 0;
    const int blockMode = CAVIUM_BLOCKING;

    /* init return codes */
    if (blockMode == CAVIUM_REQ_MODE)
        NitroxDevClear(&des3->asyncDev);

    while (length > 0) {
        word32 slen = length;
        if (slen > NITROX_MAX_BUF_LEN)
            slen = NITROX_MAX_BUF_LEN;

    #ifdef HAVE_CAVIUM_V
        cav_ret = CspEncrypt3Des(des3->asyncDev.nitrox.devId, blockMode,
            DMA_DIRECT_DIRECT, CAVIUM_SSL_GRP, CAVIUM_DPORT,
            des3->asyncDev.nitrox.contextHandle, FROM_DPTR, FROM_CTX, DES3_CBC,
            (byte*)des3->devKey, (byte*)des3->reg, (word16)slen,
            (byte*)in + offset, out + offset, &des3->asyncDev.nitrox.reqId);
    #else
        cav_ret = CspEncrypt3Des(blockMode,
            des3->asyncDev.nitrox.contextHandle, CAVIUM_NO_UPDATE, (word16)slen,
            (byte*)in + offset, out + offset, (byte*)des3->reg,
            (byte*)des3->devKey, &des3->asyncDev.nitrox.reqId,
            des3->asyncDev.nitrox.devId);
    #endif
        ret = NitroxTranslateResponseCode(cav_ret);
        if (ret != 0) {
            break;
        }
        length -= slen;
        offset += slen;

        XMEMCPY(des3->reg, out + offset - DES_BLOCK_SIZE, DES_BLOCK_SIZE);
    }

#ifdef WOLFSSL_NITROX_DEBUG
    printf("NitroxDes3CbcEncrypt: ret %x (%d), in %p, out %p, sz %d\n",
        cav_ret, ret, in, out, offset);
#endif

    return ret;
}

int NitroxDes3CbcDecrypt(Des3* des3, byte* out, const byte* in, word32 length)
{
    int ret = 0, cav_ret = 0;
    int offset = 0;
    const int blockMode = CAVIUM_BLOCKING;

    /* init return codes */
    if (blockMode == CAVIUM_REQ_MODE)
        NitroxDevClear(&des3->asyncDev);

    while (length > 0) {
        word32 slen = length;
        if (slen > NITROX_MAX_BUF_LEN)
            slen = NITROX_MAX_BUF_LEN;

        XMEMCPY(des3->tmp, in + offset + slen - DES_BLOCK_SIZE, DES_BLOCK_SIZE);

    #ifdef HAVE_CAVIUM_V
        cav_ret = CspDecrypt3Des(des3->asyncDev.nitrox.devId, blockMode,
            DMA_DIRECT_DIRECT, CAVIUM_SSL_GRP, CAVIUM_DPORT,
            des3->asyncDev.nitrox.contextHandle, FROM_DPTR, FROM_CTX, DES3_CBC,
            (byte*)des3->devKey, (byte*)des3->reg, (word16)slen,
            (byte*)in + offset, out + offset, &des3->asyncDev.nitrox.reqId);
    #else
        cav_ret = CspDecrypt3Des(blockMode,
            des3->asyncDev.nitrox.contextHandle, CAVIUM_NO_UPDATE, (word16)slen,
            (byte*)in + offset, out + offset, (byte*)des3->reg,
            (byte*)des3->devKey, &des3->asyncDev.nitrox.reqId,
            des3->asyncDev.nitrox.devId);
    #endif
        ret = NitroxTranslateResponseCode(cav_ret);
        if (ret != 0) {
            break;
        }
        length -= slen;
        offset += slen;

        XMEMCPY(des3->reg, des3->tmp, DES_BLOCK_SIZE);
    }

#ifdef WOLFSSL_NITROX_DEBUG
    printf("NitroxDes3CbcDecrypt: ret %x (%d), in %p, out %p, sz %d\n",
        cav_ret, ret, in, out, offset);
#endif

    return ret;
}
#endif /* !NO_DES3 */


#ifndef NO_HMAC
static int NitroxHmacGetType(int type)
{
    int cav_type = -1;

    /* Determine Cavium HashType */
    switch(type) {
    #ifndef NO_MD5
        case WC_MD5:
            cav_type = MD5_TYPE;
            break;
    #endif
    #ifndef NO_SHA
        case WC_SHA:
            cav_type = SHA1_TYPE;
            break;
    #endif
    #ifndef NO_SHA256
    #ifdef WOLFSSL_SHA224
        case WC_SHA224:
        #ifdef HAVE_CAVIUM_V
            cav_type = SHA2_SHA224;
        #else
            cav_type = SHA224_TYPE;
        #endif
            break;
    #endif /* WOLFSSL_SHA224 */
        case WC_SHA256:
        #ifdef HAVE_CAVIUM_V
            cav_type = SHA2_SHA256;
        #else
            cav_type = SHA256_TYPE;
        #endif
            break;
    #endif
#ifdef HAVE_CAVIUM_V
    #ifdef WOLFSSL_SHA512
        case WC_SHA512:
        #ifdef HAVE_CAVIUM_V
            cav_type = SHA2_SHA512;
        #else
            cav_type = SHA512_TYPE;
        #endif
            break;
    #endif
    #ifdef WOLFSSL_SHA384
        case WC_SHA384:
        #ifdef HAVE_CAVIUM_V
            cav_type = SHA2_SHA384;
        #else
            cav_type = SHA384_TYPE;
        #endif
            break;
    #endif
    #ifdef WOLFSSL_SHA3
        case WC_SHA3_224:
            cav_type = SHA3_SHA224;
            break;
        case WC_SHA3_256:
            cav_type = SHA3_SHA256;
            break;
        case WC_SHA3_384:
            cav_type = SHA3_SHA384;
            break;
        case WC_SHA3_512:
            cav_type = SHA3_SHA512;
            break;
    #endif /* WOLFSSL_SHA3 */
#endif /* HAVE_CAVIUM_V */
        default:
            WOLFSSL_MSG("unsupported cavium hmac type");
            cav_type = -1;
            break;
    }

    return cav_type;
}

int NitroxHmacUpdate(Hmac* hmac, const byte* msg, word32 length)
{
    int ret;
    int cav_type = NitroxHmacGetType(hmac->macType);
    const int blockMode = CAVIUM_BLOCKING;

    if (cav_type == -1) {
        return NOT_COMPILED_IN;
    }

    /* init return codes */
    if (blockMode == CAVIUM_REQ_MODE)
        NitroxDevClear(&hmac->asyncDev);

    if (hmac->innerHashKeyed == 0) {  /* starting new */
    #ifdef HAVE_CAVIUM_V
        int digest_sz = wc_HmacSizeByType(hmac->macType);
        ret = CspHmacStart(hmac->asyncDev.nitrox.devId, blockMode,
            DMA_DIRECT_DIRECT, CAVIUM_SSL_GRP, CAVIUM_DPORT,
            hmac->asyncDev.nitrox.contextHandle, cav_type,
            hmac->keyLen, (byte*)hmac->ipad, length, (Uint8*)msg,
            digest_sz, &hmac->asyncDev.nitrox.reqId);
    #else
        ret = CspHmacStart(blockMode, hmac->asyncDev.nitrox.contextHandle,
            cav_type, hmac->keyLen, (byte*)hmac->ipad, length, msg,
            &hmac->asyncDev.nitrox.reqId, hmac->asyncDev.nitrox.devId);
    #endif

        hmac->innerHashKeyed = 1;
    }
    else {
        /* do update */

    #ifdef HAVE_CAVIUM_V
        ret = CspHmacUpdate(hmac->asyncDev.nitrox.devId, blockMode,
            DMA_DIRECT_DIRECT, CAVIUM_SSL_GRP, CAVIUM_DPORT,
            hmac->asyncDev.nitrox.contextHandle, cav_type,
            length, (Uint8*)msg, &hmac->asyncDev.nitrox.reqId);
    #else
        ret = CspHmacUpdate(blockMode, hmac->asyncDev.nitrox.contextHandle,
            cav_type, length, msg,
            &hmac->asyncDev.nitrox.reqId, hmac->asyncDev.nitrox.devId);
    #endif
    }

#ifdef WOLFSSL_NITROX_DEBUG
    printf("NitroxHmacUpdate: ret %x, msg %p, length %d\n", ret, msg, length);
#endif

    ret = NitroxTranslateResponseCode(ret);
    if (ret != 0) {
        return ret;
    }

    return 0;
}

int NitroxHmacFinal(Hmac* hmac, byte* hash, word16 hashLen)
{
    int ret;
    int cav_type = NitroxHmacGetType(hmac->macType);
    const int blockMode = CAVIUM_BLOCKING;

    if (cav_type == -1) {
        return NOT_COMPILED_IN;
    }

    /* init return codes */
    if (blockMode == CAVIUM_REQ_MODE)
        NitroxDevClear(&hmac->asyncDev);

#ifdef HAVE_CAVIUM_V
    ret = CspHmacFinish(hmac->asyncDev.nitrox.devId, blockMode,
        DMA_DIRECT_DIRECT, CAVIUM_SSL_GRP, CAVIUM_DPORT,
        hmac->asyncDev.nitrox.contextHandle, cav_type,
        0, NULL, hashLen, hash,
        &hmac->asyncDev.nitrox.reqId);
#else
    (void)hashLen;
    ret = CspHmacFinish(blockMode, hmac->asyncDev.nitrox.contextHandle,
        cav_type, 0, NULL, hash,
        &hmac->asyncDev.nitrox.reqId, hmac->asyncDev.nitrox.devId);
#endif

#ifdef WOLFSSL_NITROX_DEBUG
    printf("NitroxHmacFinal: ret %x, hash %p, hashLen %d\n",
        ret, hash, hashLen);
#endif

    ret = NitroxTranslateResponseCode(ret);
    if (ret != 0) {
        return ret;
    }

    hmac->innerHashKeyed = 0;  /* tell update to start over if used again */

    return ret;
}
#endif /* !NO_HMAC */

int NitroxRngGenerateBlock(WC_RNG* rng, byte* output, word32 sz)
{
    int ret = 0, cav_ret = 0;
    word32    offset = 0;
    CavReqId  requestId;
    const int blockMode = CAVIUM_BLOCKING;

    /* init return codes */
    if (blockMode == CAVIUM_REQ_MODE)
        NitroxDevClear(&rng->asyncDev);

    while (sz > 0) {
        word32 slen = sz;
        if (slen > NITROX_MAX_BUF_LEN)
            slen = NITROX_MAX_BUF_LEN;

    #ifdef HAVE_CAVIUM_V
        cav_ret = CspTrueRandom(rng->asyncDev.nitrox.devId, blockMode,
            DMA_DIRECT_DIRECT, CAVIUM_SSL_GRP, CAVIUM_DPORT, (word16)slen,
            output + offset, &requestId);
    #else
        cav_ret = CspRandom(blockMode, (word16)slen, output + offset,
            &requestId, rng->asyncDev.nitrox.devId);
    #endif
        ret = NitroxTranslateResponseCode(cav_ret);
        if (ret != 0) {
            break;
        }

        sz     -= slen;
        offset += slen;
    }

#ifdef WOLFSSL_NITROX_DEBUG
    printf("NitroxRngGenerateBlock: ret %x (%d), output %p, sz %d\n",
        cav_ret, ret, output, offset);
#endif

    return ret;
}

#endif /* WOLFSSL_ASYNC_CRYPT */

#endif /* HAVE_CAVIUM */
