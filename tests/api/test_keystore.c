/* test_keystore.c
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


#include <tests/unit.h>
#include <tests/api/test_keystore.h>

#if defined(WOLF_CRYPTO_CB) && defined(WOLF_CRYPTO_CB_KEYSTORE)

#include <wolfssl/wolfcrypt/wc_keystore.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#define KS_TEST_DEVID 7654

/* What the last dispatch carried, so a test can assert the callback saw the
 * arguments the caller passed rather than only that the call returned 0. */
typedef struct KsSeen {
    int         op;
    int         calls;
    const void* ctx;
    const byte* outBuf;        /* the caller's output buffer, for exports */
    const byte* keyRef;
    word32      keyRefSz;
    const byte* otherRef;
    word32      otherRefSz;
    word32      format;
    word32      kdfType;
    word32      attrs;
    word32      keyType;
    word32      keySz;
    word32      blobSz;
    const byte* deriv;
    word32      derivSz;
} KsSeen;

static int KsCb(int devIdArg, wc_CryptoInfo* info, void* ctx)
{
    KsSeen* seen = (KsSeen*)ctx;

    (void)devIdArg;

    if (info == NULL || info->algo_type != WC_ALGO_TYPE_KEYSTORE) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    seen->calls++;
    seen->op  = info->keystore.type;
    seen->ctx = info->keystore.ctx;

    switch (info->keystore.type) {
        case WC_KEYSTORE_IMPORT_PLAIN:
            seen->keyRef   = info->keystore.op.importPlain.keyRef;
            seen->keyRefSz = info->keystore.op.importPlain.keyRefSz;
            seen->keyType  = info->keystore.op.importPlain.keyType;
            seen->otherRef = info->keystore.op.importPlain.key;
            seen->keySz    = info->keystore.op.importPlain.keySz;
            seen->attrs    = info->keystore.op.importPlain.attrs;
            break;
        case WC_KEYSTORE_EXPORT_PLAIN:
            seen->keyRef   = info->keystore.op.exportPlain.keyRef;
            seen->keyRefSz = info->keystore.op.exportPlain.keyRefSz;
            seen->outBuf   = info->keystore.op.exportPlain.key;
            /* answer the size query so the caller can check it propagates */
            if (info->keystore.op.exportPlain.key == NULL) {
                *info->keystore.op.exportPlain.keySz = 32;
            }
            break;
        case WC_KEYSTORE_IMPORT_WRAPPED:
            seen->keyRef     = info->keystore.op.importWrapped.keyRef;
            seen->keyRefSz   = info->keystore.op.importWrapped.keyRefSz;
            seen->keyType    = info->keystore.op.importWrapped.keyType;
            seen->otherRef   = info->keystore.op.importWrapped.wrapKeyRef;
            seen->otherRefSz = info->keystore.op.importWrapped.wrapKeyRefSz;
            seen->format     = info->keystore.op.importWrapped.format;
            seen->blobSz   = info->keystore.op.importWrapped.blobSz;
            seen->attrs    = info->keystore.op.importWrapped.attrs;
            break;
        case WC_KEYSTORE_EXPORT_WRAPPED:
            seen->keyRef     = info->keystore.op.exportWrapped.keyRef;
            seen->keyRefSz   = info->keystore.op.exportWrapped.keyRefSz;
            seen->otherRef   = info->keystore.op.exportWrapped.wrapKeyRef;
            seen->otherRefSz = info->keystore.op.exportWrapped.wrapKeyRefSz;
            seen->format     = info->keystore.op.exportWrapped.format;
            seen->outBuf     = info->keystore.op.exportWrapped.blob;
            /* answer the size query so the caller can check it propagates */
            if (info->keystore.op.exportWrapped.blob == NULL) {
                *info->keystore.op.exportWrapped.blobSz = 40;
            }
            break;
        case WC_KEYSTORE_DERIVE:
            seen->keyRef     = info->keystore.op.derive.keyRef;
            seen->keyRefSz   = info->keystore.op.derive.keyRefSz;
            seen->otherRef   = info->keystore.op.derive.srcKeyRef;
            seen->otherRefSz = info->keystore.op.derive.srcKeyRefSz;
            seen->keyType    = info->keystore.op.derive.keyType;
            seen->attrs    = info->keystore.op.derive.attrs;
            seen->kdfType  = info->keystore.op.derive.kdfType;
            seen->deriv    = info->keystore.op.derive.deriv;
            seen->derivSz  = info->keystore.op.derive.derivSz;
            break;
        case WC_KEYSTORE_DELETE:
            seen->keyRef   = info->keystore.op.deleteKey.keyRef;
            seen->keyRefSz = info->keystore.op.deleteKey.keyRefSz;
            break;
        case WC_KEYSTORE_GET_INFO:
            seen->keyRef   = info->keystore.op.getInfo.keyRef;
            seen->keyRefSz = info->keystore.op.getInfo.keyRefSz;
            /* each output is optional; a device must not assume otherwise */
            if (info->keystore.op.getInfo.keyType != NULL) {
                *info->keystore.op.getInfo.keyType = WC_KEYSTORE_KEY_WRAP;
            }
            if (info->keystore.op.getInfo.keySz != NULL) {
                *info->keystore.op.getInfo.keySz = 256;
            }
            if (info->keystore.op.getInfo.attrs != NULL) {
                *info->keystore.op.getInfo.attrs = WC_KEYSTORE_ATTR_UNWRAP_ONLY;
            }
            break;
        default:
            return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    return 0;
}

static const byte ksPlain[]    = { 0x30, 0x31, 0x32, 0x33, 0x34 };
static const byte ksKeyRef[]   = { 0x01, 0x02, 0x03, 0x04 };
static const byte ksOtherRef[] = { 0x11, 0x12 };
static const byte ksBlob[]     = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
static const byte ksDeriv[]    = { 0x21, 0x22, 0x23 };
/* Sentinel for the caller context every entry point forwards untouched. */
static const byte ksCallerCtx[] = { 0x5a };

#endif /* WOLF_CRYPTO_CB && WOLF_CRYPTO_CB_KEYSTORE */

int test_wc_KeyStore_ImportPlain(void)
{
    EXPECT_DECLS;
#if defined(WOLF_CRYPTO_CB) && defined(WOLF_CRYPTO_CB_KEYSTORE)
    KsSeen seen;

    XMEMSET(&seen, 0, sizeof(seen));
    ExpectIntEQ(wc_CryptoCb_RegisterDevice(KS_TEST_DEVID, KsCb, &seen), 0);

    /* WC_KEYSTORE_KEY_WRAP and WC_KEYSTORE_ATTR_EXPORTABLE are both 1, so a
     * swap would compile and run. Assert each landed in its own field. */
    ExpectIntEQ(wc_KeyStore_ImportPlain(KS_TEST_DEVID,
        ksKeyRef, (word32)sizeof(ksKeyRef),
        WC_KEYSTORE_KEY_HMAC, ksPlain, (word32)sizeof(ksPlain),
        WC_KEYSTORE_ATTR_EXPORTABLE, ksCallerCtx), 0);
    ExpectIntEQ(seen.op, WC_KEYSTORE_IMPORT_PLAIN);
    ExpectPtrEq(seen.keyRef, ksKeyRef);
    ExpectIntEQ(seen.keyRefSz, (word32)sizeof(ksKeyRef));
    ExpectIntEQ(seen.keyType, WC_KEYSTORE_KEY_HMAC);
    ExpectPtrEq(seen.otherRef, ksPlain);
    ExpectIntEQ(seen.keySz, (word32)sizeof(ksPlain));
    ExpectIntEQ(seen.attrs, WC_KEYSTORE_ATTR_EXPORTABLE);
    ExpectPtrEq(seen.ctx, ksCallerCtx);

    /* arguments are validated before the device is consulted */
    seen.calls = 0;
    ExpectIntEQ(wc_KeyStore_ImportPlain(KS_TEST_DEVID, NULL, 0,
        WC_KEYSTORE_KEY_AES, ksPlain, (word32)sizeof(ksPlain), 0, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_KeyStore_ImportPlain(KS_TEST_DEVID,
        ksKeyRef, (word32)sizeof(ksKeyRef),
        WC_KEYSTORE_KEY_AES, NULL, 0, 0, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(seen.calls, 0);

    wc_CryptoCb_UnRegisterDevice(KS_TEST_DEVID);
#endif
    return EXPECT_RESULT();
}

int test_wc_KeyStore_ExportPlain(void)
{
    EXPECT_DECLS;
#if defined(WOLF_CRYPTO_CB) && defined(WOLF_CRYPTO_CB_KEYSTORE)
    KsSeen seen;
    byte   out[64];
    word32 outSz = (word32)sizeof(out);

    XMEMSET(&seen, 0, sizeof(seen));
    ExpectIntEQ(wc_CryptoCb_RegisterDevice(KS_TEST_DEVID, KsCb, &seen), 0);

    ExpectIntEQ(wc_KeyStore_ExportPlain(KS_TEST_DEVID,
        ksKeyRef, (word32)sizeof(ksKeyRef), out, &outSz, ksCallerCtx), 0);
    ExpectIntEQ(seen.op, WC_KEYSTORE_EXPORT_PLAIN);
    ExpectPtrEq(seen.keyRef, ksKeyRef);
    ExpectIntEQ(seen.keyRefSz, (word32)sizeof(ksKeyRef));
    ExpectPtrEq(seen.ctx, ksCallerCtx);
    /* the device must be handed the caller's own buffer to write into */
    ExpectPtrEq(seen.outBuf, out);

    /* key == NULL is the size query and must still reach the device */
    outSz = 0;
    ExpectIntEQ(wc_KeyStore_ExportPlain(KS_TEST_DEVID,
        ksKeyRef, (word32)sizeof(ksKeyRef), NULL, &outSz, NULL), 0);
    ExpectIntEQ(outSz, 32);
    ExpectPtrEq(seen.outBuf, NULL);

    /* a buffer with no size is not a size query, it is a mistake */
    seen.calls = 0;
    outSz = 0;
    ExpectIntEQ(wc_KeyStore_ExportPlain(KS_TEST_DEVID,
        ksKeyRef, (word32)sizeof(ksKeyRef), out, &outSz, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_KeyStore_ExportPlain(KS_TEST_DEVID,
        ksKeyRef, (word32)sizeof(ksKeyRef), out, NULL, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(seen.calls, 0);

    wc_CryptoCb_UnRegisterDevice(KS_TEST_DEVID);
#endif
    return EXPECT_RESULT();
}

int test_wc_KeyStore_ImportWrapped(void)
{
    EXPECT_DECLS;
#if defined(WOLF_CRYPTO_CB) && defined(WOLF_CRYPTO_CB_KEYSTORE)
    KsSeen seen;

    XMEMSET(&seen, 0, sizeof(seen));
    ExpectIntEQ(wc_CryptoCb_RegisterDevice(KS_TEST_DEVID, KsCb, &seen), 0);

    ExpectIntEQ(wc_KeyStore_ImportWrapped(KS_TEST_DEVID,
        ksKeyRef, (word32)sizeof(ksKeyRef), WC_KEYSTORE_KEY_AES,
        ksOtherRef, (word32)sizeof(ksOtherRef),
        WC_KEYWRAP_FORMAT_VENDOR, ksBlob, (word32)sizeof(ksBlob),
        WC_KEYSTORE_ATTR_PERSISTENT, ksCallerCtx), 0);
    ExpectIntEQ(seen.op, WC_KEYSTORE_IMPORT_WRAPPED);
    ExpectIntEQ(seen.keyType, WC_KEYSTORE_KEY_AES);
    ExpectIntEQ(seen.attrs, WC_KEYSTORE_ATTR_PERSISTENT);
    ExpectPtrEq(seen.keyRef, ksKeyRef);
    ExpectIntEQ(seen.keyRefSz, (word32)sizeof(ksKeyRef));
    ExpectPtrEq(seen.otherRef, ksOtherRef);
    ExpectIntEQ(seen.otherRefSz, (word32)sizeof(ksOtherRef));
    ExpectIntEQ(seen.format, WC_KEYWRAP_FORMAT_VENDOR);
    ExpectIntEQ(seen.blobSz, (word32)sizeof(ksBlob));
    ExpectPtrEq(seen.ctx, ksCallerCtx);

    /* arguments are validated before the device is consulted */
    seen.calls = 0;
    ExpectIntEQ(wc_KeyStore_ImportWrapped(KS_TEST_DEVID, NULL, 0,
        WC_KEYSTORE_KEY_AES, ksOtherRef, (word32)sizeof(ksOtherRef),
        WC_KEYWRAP_FORMAT_VENDOR, ksBlob, (word32)sizeof(ksBlob), 0, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_KeyStore_ImportWrapped(KS_TEST_DEVID,
        ksKeyRef, (word32)sizeof(ksKeyRef), WC_KEYSTORE_KEY_AES,
        ksOtherRef, (word32)sizeof(ksOtherRef),
        WC_KEYWRAP_FORMAT_VENDOR, NULL, 0, 0, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* A NULL wrapping key means "use the device's own", so a length beside
     * it is a caller mistake rather than an implicit-key request. */
    ExpectIntEQ(wc_KeyStore_ImportWrapped(KS_TEST_DEVID,
        ksKeyRef, (word32)sizeof(ksKeyRef), WC_KEYSTORE_KEY_AES,
        NULL, (word32)sizeof(ksOtherRef),
        WC_KEYWRAP_FORMAT_VENDOR, ksBlob, (word32)sizeof(ksBlob), 0, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(seen.calls, 0);

    /* The implicit wrapping key: NULL with no length reaches the device. */
    ExpectIntEQ(wc_KeyStore_ImportWrapped(KS_TEST_DEVID,
        ksKeyRef, (word32)sizeof(ksKeyRef), WC_KEYSTORE_KEY_AES, NULL, 0,
        WC_KEYWRAP_FORMAT_VENDOR, ksBlob, (word32)sizeof(ksBlob), 0, NULL),
        0);
    ExpectIntEQ(seen.op, WC_KEYSTORE_IMPORT_WRAPPED);
    ExpectPtrEq(seen.otherRef, NULL);
    ExpectIntEQ(seen.otherRefSz, 0);

    wc_CryptoCb_UnRegisterDevice(KS_TEST_DEVID);
#endif
    return EXPECT_RESULT();
}

int test_wc_KeyStore_ExportWrapped(void)
{
    EXPECT_DECLS;
#if defined(WOLF_CRYPTO_CB) && defined(WOLF_CRYPTO_CB_KEYSTORE)
    KsSeen seen;
    byte   out[64];
    word32 outSz = (word32)sizeof(out);

    XMEMSET(&seen, 0, sizeof(seen));
    ExpectIntEQ(wc_CryptoCb_RegisterDevice(KS_TEST_DEVID, KsCb, &seen), 0);

    ExpectIntEQ(wc_KeyStore_ExportWrapped(KS_TEST_DEVID,
        ksKeyRef, (word32)sizeof(ksKeyRef),
        ksOtherRef, (word32)sizeof(ksOtherRef),
        WC_KEYWRAP_FORMAT_AESKW, out, &outSz, ksCallerCtx), 0);
    ExpectIntEQ(seen.op, WC_KEYSTORE_EXPORT_WRAPPED);
    /* Which reference is the key and which is the KEK: a transposition in the
     * dispatcher is invisible without this. */
    ExpectPtrEq(seen.keyRef, ksKeyRef);
    ExpectIntEQ(seen.keyRefSz, (word32)sizeof(ksKeyRef));
    ExpectPtrEq(seen.otherRef, ksOtherRef);
    ExpectIntEQ(seen.otherRefSz, (word32)sizeof(ksOtherRef));
    ExpectIntEQ(seen.format, WC_KEYWRAP_FORMAT_AESKW);
    ExpectPtrEq(seen.ctx, ksCallerCtx);
    /* the device must be handed the caller's own buffer to write into */
    ExpectPtrEq(seen.outBuf, out);

    /* blob == NULL is the size query and must still reach the device */
    outSz = 0;
    ExpectIntEQ(wc_KeyStore_ExportWrapped(KS_TEST_DEVID,
        ksKeyRef, (word32)sizeof(ksKeyRef),
        ksOtherRef, (word32)sizeof(ksOtherRef),
        WC_KEYWRAP_FORMAT_AESKW, NULL, &outSz, NULL), 0);
    ExpectIntEQ(outSz, 40);
    ExpectPtrEq(seen.outBuf, NULL);

    /* a buffer with no size is not a size query, it is a mistake */
    seen.calls = 0;
    outSz = 0;
    ExpectIntEQ(wc_KeyStore_ExportWrapped(KS_TEST_DEVID,
        ksKeyRef, (word32)sizeof(ksKeyRef),
        ksOtherRef, (word32)sizeof(ksOtherRef),
        WC_KEYWRAP_FORMAT_AESKW, out, &outSz, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_KeyStore_ExportWrapped(KS_TEST_DEVID,
        ksKeyRef, (word32)sizeof(ksKeyRef),
        ksOtherRef, (word32)sizeof(ksOtherRef),
        WC_KEYWRAP_FORMAT_AESKW, out, NULL, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    outSz = (word32)sizeof(out);
    ExpectIntEQ(wc_KeyStore_ExportWrapped(KS_TEST_DEVID,
        ksKeyRef, (word32)sizeof(ksKeyRef),
        NULL, (word32)sizeof(ksOtherRef),
        WC_KEYWRAP_FORMAT_AESKW, out, &outSz, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(seen.calls, 0);

    /* The implicit wrapping key: NULL with no length reaches the device. */
    outSz = (word32)sizeof(out);
    ExpectIntEQ(wc_KeyStore_ExportWrapped(KS_TEST_DEVID,
        ksKeyRef, (word32)sizeof(ksKeyRef), NULL, 0,
        WC_KEYWRAP_FORMAT_AESKW, out, &outSz, NULL), 0);
    ExpectIntEQ(seen.op, WC_KEYSTORE_EXPORT_WRAPPED);
    ExpectPtrEq(seen.otherRef, NULL);
    ExpectIntEQ(seen.otherRefSz, 0);

    wc_CryptoCb_UnRegisterDevice(KS_TEST_DEVID);
#endif
    return EXPECT_RESULT();
}

int test_wc_KeyStore_Derive(void)
{
    EXPECT_DECLS;
#if defined(WOLF_CRYPTO_CB) && defined(WOLF_CRYPTO_CB_KEYSTORE)
    KsSeen seen;

    XMEMSET(&seen, 0, sizeof(seen));
    ExpectIntEQ(wc_CryptoCb_RegisterDevice(KS_TEST_DEVID, KsCb, &seen), 0);

    /* WC_KDF_TYPE_HKDF and WC_KEYSTORE_ATTR_EXPORTABLE are both 1, so keep
     * kdfType and attrs numerically apart or a transposition reads as equal. */
    ExpectIntEQ(wc_KeyStore_Derive(KS_TEST_DEVID,
        ksKeyRef, (word32)sizeof(ksKeyRef), WC_KEYSTORE_KEY_AES,
        ksOtherRef, (word32)sizeof(ksOtherRef),
        WC_KDF_TYPE_HKDF, ksDeriv, (word32)sizeof(ksDeriv),
        WC_KEYSTORE_ATTR_PERSISTENT, ksCallerCtx), 0);
    ExpectIntEQ(seen.op, WC_KEYSTORE_DERIVE);
    ExpectIntEQ(seen.keyType, WC_KEYSTORE_KEY_AES);
    ExpectPtrEq(seen.keyRef, ksKeyRef);
    ExpectIntEQ(seen.keyRefSz, (word32)sizeof(ksKeyRef));
    ExpectPtrEq(seen.otherRef, ksOtherRef);
    ExpectIntEQ(seen.otherRefSz, (word32)sizeof(ksOtherRef));
    ExpectIntEQ(seen.attrs, WC_KEYSTORE_ATTR_PERSISTENT);
    ExpectIntEQ(seen.kdfType, WC_KDF_TYPE_HKDF);
    ExpectPtrEq(seen.deriv, ksDeriv);
    ExpectIntEQ(seen.derivSz, (word32)sizeof(ksDeriv));
    ExpectPtrEq(seen.ctx, ksCallerCtx);

    /* WC_KDF_TYPE_NONE asks for the device's own derivation */
    ExpectIntEQ(wc_KeyStore_Derive(KS_TEST_DEVID,
        ksKeyRef, (word32)sizeof(ksKeyRef), WC_KEYSTORE_KEY_NONE,
        ksOtherRef, (word32)sizeof(ksOtherRef),
        WC_KDF_TYPE_NONE, ksDeriv, (word32)sizeof(ksDeriv),
        WC_KEYSTORE_ATTR_EXPORTABLE, NULL), 0);
    ExpectIntEQ(seen.kdfType, WC_KDF_TYPE_NONE);
    ExpectIntEQ(seen.attrs, WC_KEYSTORE_ATTR_EXPORTABLE);

    seen.calls = 0;
    ExpectIntEQ(wc_KeyStore_Derive(KS_TEST_DEVID,
        ksKeyRef, (word32)sizeof(ksKeyRef), WC_KEYSTORE_KEY_AES, NULL, 0,
        WC_KDF_TYPE_NONE, ksDeriv, (word32)sizeof(ksDeriv), 0, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* No derivation data means no length beside it. */
    ExpectIntEQ(wc_KeyStore_Derive(KS_TEST_DEVID,
        ksKeyRef, (word32)sizeof(ksKeyRef), WC_KEYSTORE_KEY_AES,
        ksOtherRef, (word32)sizeof(ksOtherRef),
        WC_KDF_TYPE_NONE, NULL, (word32)sizeof(ksDeriv), 0, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(seen.calls, 0);

    wc_CryptoCb_UnRegisterDevice(KS_TEST_DEVID);
#endif
    return EXPECT_RESULT();
}

int test_wc_KeyStore_Delete(void)
{
    EXPECT_DECLS;
#if defined(WOLF_CRYPTO_CB) && defined(WOLF_CRYPTO_CB_KEYSTORE)
    KsSeen seen;

    XMEMSET(&seen, 0, sizeof(seen));
    ExpectIntEQ(wc_CryptoCb_RegisterDevice(KS_TEST_DEVID, KsCb, &seen), 0);

    ExpectIntEQ(wc_KeyStore_Delete(KS_TEST_DEVID,
        ksKeyRef, (word32)sizeof(ksKeyRef), ksCallerCtx), 0);
    ExpectIntEQ(seen.op, WC_KEYSTORE_DELETE);
    ExpectPtrEq(seen.keyRef, ksKeyRef);
    ExpectIntEQ(seen.keyRefSz, (word32)sizeof(ksKeyRef));
    ExpectPtrEq(seen.ctx, ksCallerCtx);

    seen.calls = 0;
    ExpectIntEQ(wc_KeyStore_Delete(KS_TEST_DEVID, ksKeyRef, 0, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(seen.calls, 0);

    wc_CryptoCb_UnRegisterDevice(KS_TEST_DEVID);
#endif
    return EXPECT_RESULT();
}

int test_wc_KeyStore_GetInfo(void)
{
    EXPECT_DECLS;
#if defined(WOLF_CRYPTO_CB) && defined(WOLF_CRYPTO_CB_KEYSTORE)
    KsSeen seen;
    word32 keyType = 0xDEADBEEF;
    word32 keySz   = 0xDEADBEEF;
    word32 attrs   = 0xDEADBEEF;

    XMEMSET(&seen, 0, sizeof(seen));
    ExpectIntEQ(wc_CryptoCb_RegisterDevice(KS_TEST_DEVID, KsCb, &seen), 0);

    /* A wrapping key must be nameable: NONE here is indistinguishable from
     * an empty slot. */
    ExpectIntEQ(wc_KeyStore_GetInfo(KS_TEST_DEVID,
        ksKeyRef, (word32)sizeof(ksKeyRef), &keyType, &keySz, &attrs,
        ksCallerCtx), 0);
    ExpectIntEQ(seen.op, WC_KEYSTORE_GET_INFO);
    ExpectPtrEq(seen.keyRef, ksKeyRef);
    ExpectIntEQ(seen.keyRefSz, (word32)sizeof(ksKeyRef));
    ExpectIntEQ(keyType, WC_KEYSTORE_KEY_WRAP);
    ExpectIntEQ(keySz, 256);
    ExpectIntEQ(attrs, WC_KEYSTORE_ATTR_UNWRAP_ONLY);
    ExpectPtrEq(seen.ctx, ksCallerCtx);

    /* Each output is optional and asked for on its own. */
    keyType = 0xDEADBEEF;
    ExpectIntEQ(wc_KeyStore_GetInfo(KS_TEST_DEVID,
        ksKeyRef, (word32)sizeof(ksKeyRef), &keyType, NULL, NULL, NULL), 0);
    ExpectIntEQ(keyType, WC_KEYSTORE_KEY_WRAP);
    keySz = 0xDEADBEEF;
    ExpectIntEQ(wc_KeyStore_GetInfo(KS_TEST_DEVID,
        ksKeyRef, (word32)sizeof(ksKeyRef), NULL, &keySz, NULL, NULL), 0);
    ExpectIntEQ(keySz, 256);
    attrs = 0xDEADBEEF;
    ExpectIntEQ(wc_KeyStore_GetInfo(KS_TEST_DEVID,
        ksKeyRef, (word32)sizeof(ksKeyRef), NULL, NULL, &attrs, NULL), 0);
    ExpectIntEQ(attrs, WC_KEYSTORE_ATTR_UNWRAP_ONLY);

    /* Asking for nothing still reaches the device, and writes nowhere. */
    ExpectIntEQ(wc_KeyStore_GetInfo(KS_TEST_DEVID,
        ksKeyRef, (word32)sizeof(ksKeyRef), NULL, NULL, NULL, NULL), 0);

    /* arguments are validated before the device is consulted */
    seen.calls = 0;
    ExpectIntEQ(wc_KeyStore_GetInfo(KS_TEST_DEVID, NULL, 0,
        &keyType, &keySz, &attrs, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_KeyStore_GetInfo(KS_TEST_DEVID, ksKeyRef, 0,
        &keyType, &keySz, &attrs, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(seen.calls, 0);

    wc_CryptoCb_UnRegisterDevice(KS_TEST_DEVID);
#endif
    return EXPECT_RESULT();
}

int test_wc_KeyStore_NoDevice(void)
{
    EXPECT_DECLS;
#if defined(WOLF_CRYPTO_CB) && defined(WOLF_CRYPTO_CB_KEYSTORE)
    word32 keyType = 0, keySz = 0, attrs = 0;

    /* Nothing registered: every entry point must decline. */
    ExpectIntEQ(wc_KeyStore_Delete(KS_TEST_DEVID,
        ksKeyRef, (word32)sizeof(ksKeyRef), NULL),
        WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE));
    ExpectIntEQ(wc_KeyStore_GetInfo(KS_TEST_DEVID,
        ksKeyRef, (word32)sizeof(ksKeyRef), &keyType, &keySz, &attrs, NULL),
        WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE));
    ExpectIntEQ(wc_KeyStore_Derive(KS_TEST_DEVID,
        ksKeyRef, (word32)sizeof(ksKeyRef), WC_KEYSTORE_KEY_AES,
        ksOtherRef, (word32)sizeof(ksOtherRef),
        WC_KDF_TYPE_NONE, ksDeriv, (word32)sizeof(ksDeriv), 0, NULL),
        WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE));
    ExpectIntEQ(wc_KeyStore_ImportPlain(KS_TEST_DEVID,
        ksKeyRef, (word32)sizeof(ksKeyRef),
        WC_KEYSTORE_KEY_AES, ksPlain, (word32)sizeof(ksPlain), 0, NULL),
        WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE));
    ExpectIntEQ(wc_KeyStore_ExportPlain(KS_TEST_DEVID,
        ksKeyRef, (word32)sizeof(ksKeyRef), NULL, &keySz, NULL),
        WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE));
    ExpectIntEQ(wc_KeyStore_ImportWrapped(KS_TEST_DEVID,
        ksKeyRef, (word32)sizeof(ksKeyRef), WC_KEYSTORE_KEY_AES,
        ksOtherRef, (word32)sizeof(ksOtherRef),
        WC_KEYWRAP_FORMAT_AESKW, ksBlob, (word32)sizeof(ksBlob), 0, NULL),
        WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE));
    keySz = 0;
    ExpectIntEQ(wc_KeyStore_ExportWrapped(KS_TEST_DEVID,
        ksKeyRef, (word32)sizeof(ksKeyRef),
        ksOtherRef, (word32)sizeof(ksOtherRef),
        WC_KEYWRAP_FORMAT_AESKW, NULL, &keySz, NULL),
        WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE));
#endif
    return EXPECT_RESULT();
}
