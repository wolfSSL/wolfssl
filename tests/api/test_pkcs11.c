/* test_pkcs11.c
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

#include <tests/api/api.h>
#include <tests/api/test_pkcs11.h>

#if defined(HAVE_PKCS11) && defined(HAVE_ECC) && \
    defined(HAVE_ECC_VERIFY) && !defined(WC_NO_RNG) && \
    !defined(NO_ECC256) && !defined(NO_ECC_SECP)

#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/wc_pkcs11.h>

static int test_pkcs11_verify_init_calls = 0;

static CK_RV test_pkcs11_get_mechanism_info(CK_SLOT_ID slotId,
    CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR info)
{
    (void)slotId;

    if (type != CKM_ECDSA || info == NULL)
        return CKR_MECHANISM_INVALID;

    XMEMSET(info, 0, sizeof(*info));
    info->flags = CKF_VERIFY;
    return CKR_OK;
}

static CK_RV test_pkcs11_create_object(CK_SESSION_HANDLE session,
    CK_ATTRIBUTE_PTR template, CK_ULONG count, CK_OBJECT_HANDLE_PTR object)
{
    (void)session;
    (void)template;
    (void)count;

    if (object == NULL)
        return CKR_MECHANISM_INVALID;

    *object = 1;
    return CKR_OK;
}

static CK_RV test_pkcs11_destroy_object(CK_SESSION_HANDLE session,
    CK_OBJECT_HANDLE object)
{
    (void)session;
    (void)object;

    return CKR_OK;
}

static CK_RV test_pkcs11_verify_init(CK_SESSION_HANDLE session,
    CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key)
{
    (void)session;
    (void)mechanism;
    (void)key;

    test_pkcs11_verify_init_calls++;
    return CKR_OK;
}

static CK_RV test_pkcs11_verify(CK_SESSION_HANDLE session, CK_BYTE_PTR data,
    CK_ULONG dataLen, CK_BYTE_PTR signature, CK_ULONG signatureLen)
{
    (void)session;
    (void)data;
    (void)dataLen;
    (void)signature;
    (void)signatureLen;

    return CKR_SIGNATURE_INVALID;
}

int test_wc_Pkcs11_EcdsaSigDecode(void)
{
    static const byte emptyR[] = {
        0x30, 0x05, 0x02, 0x00, 0x02, 0x01, 0x01
    };
    static const byte emptyS[] = {
        0x30, 0x05, 0x02, 0x01, 0x01, 0x02, 0x00
    };
    static const byte hash[] = { 0x00 };
    Pkcs11Token token;
    CK_FUNCTION_LIST func;
    wc_CryptoInfo info;
    ecc_key key;
    WC_RNG rng;
    int ret;
    int res = 0;
    int haveKey = 0;
    int haveRng = 0;
    EXPECT_DECLS;

    XMEMSET(&token, 0, sizeof(token));
    XMEMSET(&func, 0, sizeof(func));
    XMEMSET(&info, 0, sizeof(info));
    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(&rng, 0, sizeof(rng));

    func.C_GetMechanismInfo = test_pkcs11_get_mechanism_info;
    func.C_CreateObject = test_pkcs11_create_object;
    func.C_DestroyObject = test_pkcs11_destroy_object;
    func.C_VerifyInit = test_pkcs11_verify_init;
    func.C_Verify = test_pkcs11_verify;
    token.func = &func;
    token.slotId = 1;
    token.handle = 1;
    token.version = WC_PCKS11VERSION_2_40;

    ret = wc_InitRng(&rng);
    ExpectIntEQ(ret, 0);
    if (ret == 0)
        haveRng = 1;
    if (ret == 0)
        ret = wc_ecc_init(&key);
    ExpectIntEQ(ret, 0);
    if (ret == 0)
        haveKey = 1;
    if (ret == 0)
        ret = wc_ecc_make_key(&rng, 32, &key);
#ifdef WOLFSSL_ASYNC_CRYPT
    if (ret == WC_PENDING_E)
        ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    ExpectIntEQ(ret, 0);

    info.algo_type = WC_ALGO_TYPE_PK;
    info.pk.type = WC_PK_TYPE_ECDSA_VERIFY;
    info.pk.eccverify.hash = hash;
    info.pk.eccverify.hashlen = sizeof(hash);
    info.pk.eccverify.key = &key;
    info.pk.eccverify.res = &res;

    if (ret == 0) {
        info.pk.eccverify.sig = emptyR;
        info.pk.eccverify.siglen = sizeof(emptyR);
        test_pkcs11_verify_init_calls = 0;
        ExpectIntEQ(wc_Pkcs11_CryptoDevCb(1, &info, &token),
            WC_NO_ERR_TRACE(ASN_PARSE_E));
        ExpectIntEQ(test_pkcs11_verify_init_calls, 0);
    }

    if (ret == 0) {
        info.pk.eccverify.sig = emptyS;
        info.pk.eccverify.siglen = sizeof(emptyS);
        test_pkcs11_verify_init_calls = 0;
        ExpectIntEQ(wc_Pkcs11_CryptoDevCb(1, &info, &token),
            WC_NO_ERR_TRACE(ASN_PARSE_E));
        ExpectIntEQ(test_pkcs11_verify_init_calls, 0);
    }

    if (haveKey)
        wc_ecc_free(&key);
    if (haveRng)
        DoExpectIntEQ(wc_FreeRng(&rng), 0);

    return EXPECT_RESULT();
}

#endif
