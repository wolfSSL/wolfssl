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

#if defined(HAVE_PKCS11) && !defined(WC_NO_RNG)

#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/wc_pkcs11.h>

#if defined(HAVE_ECC) && !defined(NO_PKCS11_ECC) && \
    !defined(NO_ECC256) && !defined(NO_ECC_SECP)
    #ifdef HAVE_ECC_VERIFY
        #define TEST_PKCS11_ECDSA
    #endif
    #if defined(HAVE_ECC_DHE) && !defined(NO_PKCS11_ECDH)
        #define TEST_PKCS11_RD_ECDH
    #endif
    #if defined(HAVE_ECC_DHE) && !defined(NO_PKCS11_EC_KEYGEN)
        #define TEST_PKCS11_RD_ECGEN
    #endif
#endif
#if !defined(NO_RSA) && !defined(NO_PKCS11_RSA) && defined(WOLF_PRIVATE_KEY_ID)
    #define TEST_PKCS11_RD_RSA
#endif
#if defined(WOLFSSL_HAVE_MLDSA) && !defined(NO_PKCS11_MLDSA) && \
    !defined(WOLFSSL_MLDSA_NO_MAKE_KEY) && !defined(WOLFSSL_NO_ML_DSA_44)
    #define TEST_PKCS11_RD_MLDSA
#endif
#if defined(WOLFSSL_HAVE_MLKEM) && !defined(NO_PKCS11_MLKEM) && \
    !defined(WOLFSSL_NO_ML_KEM) && !defined(WOLFSSL_NO_ML_KEM_768)
    #ifndef WOLFSSL_MLKEM_NO_MAKE_KEY
        #define TEST_PKCS11_RD_MLKEM_GEN
    #endif
    #if !defined(WOLFSSL_MLKEM_NO_ENCAPSULATE) && defined(WOLF_PRIVATE_KEY_ID)
        #define TEST_PKCS11_RD_MLKEM_ENC
    #endif
    #ifndef WOLFSSL_MLKEM_NO_DECAPSULATE
        #define TEST_PKCS11_RD_MLKEM_DEC
    #endif
#endif
#ifndef NO_CERTS
    #define TEST_PKCS11_RD_CERT
#endif

#if defined(TEST_PKCS11_RD_ECDH) || defined(TEST_PKCS11_RD_ECGEN) || \
    defined(TEST_PKCS11_RD_RSA) || defined(TEST_PKCS11_RD_MLDSA) || \
    defined(TEST_PKCS11_RD_MLKEM_GEN) || defined(TEST_PKCS11_RD_MLKEM_ENC) || \
    defined(TEST_PKCS11_RD_MLKEM_DEC) || defined(TEST_PKCS11_RD_CERT)
    #define TEST_PKCS11_VALUE_READ
#endif

#ifdef TEST_PKCS11_ECDSA
static int         test_pkcs11_verify_init_calls = 0;
static int         test_pkcs11_verify_calls = 0;
static const byte* test_pkcs11_expected_sig = NULL;
static word32      test_pkcs11_expected_sig_len = 0;
static CK_OBJECT_HANDLE test_pkcs11_verify_key = 0;

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
#endif

#if defined(TEST_PKCS11_ECDSA) || defined(TEST_PKCS11_VALUE_READ)
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
#endif

#ifdef TEST_PKCS11_ECDSA
static CK_RV test_pkcs11_verify_init(CK_SESSION_HANDLE session,
    CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key)
{
    (void)session;
    (void)mechanism;

    test_pkcs11_verify_init_calls++;
    test_pkcs11_verify_key = key;
    return CKR_OK;
}

static CK_RV test_pkcs11_verify(CK_SESSION_HANDLE session, CK_BYTE_PTR data,
    CK_ULONG dataLen, CK_BYTE_PTR signature, CK_ULONG signatureLen)
{
    (void)session;
    (void)data;
    (void)dataLen;

    test_pkcs11_verify_calls++;
    if (test_pkcs11_expected_sig == NULL ||
        signatureLen != test_pkcs11_expected_sig_len ||
        XMEMCMP(signature, test_pkcs11_expected_sig, signatureLen) != 0) {
        return CKR_SIGNATURE_INVALID;
    }

    return CKR_OK;
}

#ifdef WOLF_PRIVATE_KEY_ID
#define TEST_PKCS11_PRIV_OBJ 3
#define TEST_PKCS11_PUB_OBJ  2

static CK_OBJECT_CLASS test_pkcs11_find_class;
static byte            test_pkcs11_params_tag = 0x06;
static byte            test_pkcs11_params_oid_len = 0x08;
static CK_ULONG        test_pkcs11_params_sz = 10;
static CK_ULONG        test_pkcs11_class_len = sizeof(CK_OBJECT_CLASS);
static int             test_pkcs11_find_class_set = 0;
static int             test_pkcs11_find_idx = 0;

static CK_RV test_pkcs11_find_objects_init(CK_SESSION_HANDLE session,
    CK_ATTRIBUTE_PTR template, CK_ULONG count)
{
    CK_ULONG i;

    (void)session;

    test_pkcs11_find_class_set = 0;
    test_pkcs11_find_idx = 0;
    for (i = 0; i < count; i++) {
        if (template[i].type == CKA_CLASS) {
            test_pkcs11_find_class = *(CK_OBJECT_CLASS*)template[i].pValue;
            test_pkcs11_find_class_set = 1;
        }
    }
    return CKR_OK;
}

static CK_RV test_pkcs11_find_objects(CK_SESSION_HANDLE session,
    CK_OBJECT_HANDLE_PTR objects, CK_ULONG maxCount, CK_ULONG_PTR count)
{
    static const CK_OBJECT_HANDLE handles[] = {
        TEST_PKCS11_PRIV_OBJ, TEST_PKCS11_PUB_OBJ
    };
    static const CK_OBJECT_CLASS classes[] = {
        CKO_PRIVATE_KEY, CKO_PUBLIC_KEY
    };

    (void)session;

    if (objects == NULL || maxCount == 0 || count == NULL)
        return CKR_MECHANISM_INVALID;

    *count = 0;
    while (test_pkcs11_find_idx < 2 && *count == 0) {
        if (!test_pkcs11_find_class_set ||
                classes[test_pkcs11_find_idx] == test_pkcs11_find_class) {
            objects[0] = handles[test_pkcs11_find_idx];
            *count = 1;
        }
        test_pkcs11_find_idx++;
    }
    return CKR_OK;
}

static CK_RV test_pkcs11_find_objects_final(CK_SESSION_HANDLE session)
{
    (void)session;

    return CKR_OK;
}

static CK_RV test_pkcs11_get_attribute_value(CK_SESSION_HANDLE session,
    CK_OBJECT_HANDLE object, CK_ATTRIBUTE_PTR template, CK_ULONG count)
{
    /* DER encoded OID of SECP256R1. */
    static const byte p256Params[] = {
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07
    };
    CK_ULONG i;

    (void)session;

    for (i = 0; i < count; i++) {
        if (template[i].type == CKA_EC_PARAMS &&
                template[i].ulValueLen >= sizeof(p256Params)) {
            XMEMCPY(template[i].pValue, p256Params, sizeof(p256Params));
            ((byte*)template[i].pValue)[0] = test_pkcs11_params_tag;
            ((byte*)template[i].pValue)[1] = test_pkcs11_params_oid_len;
            template[i].ulValueLen = test_pkcs11_params_sz;
        }
        else if (template[i].type == CKA_CLASS) {
            *(CK_OBJECT_CLASS*)template[i].pValue =
                (object == TEST_PKCS11_PUB_OBJ) ? CKO_PUBLIC_KEY :
                                                  CKO_PRIVATE_KEY;
            template[i].ulValueLen = test_pkcs11_class_len;
        }
        else {
            return CKR_MECHANISM_INVALID;
        }
    }
    return CKR_OK;
}
#endif
#endif /* TEST_PKCS11_ECDSA */

#ifdef TEST_PKCS11_VALUE_READ
#define TEST_PKCS11_RD_DEVID 0x7032

static CK_ULONG test_pkcs11_rd_len = 0;
static CK_ULONG test_pkcs11_rd_ret_len = 0;
static CK_ULONG test_pkcs11_rd_exp_short = 0;
static CK_ULONG test_pkcs11_rd_exp_len = 0;
static const byte* test_pkcs11_rd_data = NULL;
static CK_RV    test_pkcs11_rd_rv = CKR_OK;

static CK_RV test_pkcs11_rd_mech_info(CK_SLOT_ID slotId,
    CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR info)
{
    (void)slotId;
    (void)type;

    XMEMSET(info, 0, sizeof(*info));
    info->ulMaxKeySize = 0xffff;
    info->flags = CKF_DERIVE | CKF_GENERATE_KEY_PAIR | CKF_ENCAPSULATE |
                  CKF_DECAPSULATE;
    return CKR_OK;
}

static CK_RV test_pkcs11_rd_derive(CK_SESSION_HANDLE session,
    CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE baseKey,
    CK_ATTRIBUTE_PTR template, CK_ULONG count, CK_OBJECT_HANDLE_PTR key)
{
    (void)session;
    (void)mechanism;
    (void)baseKey;
    (void)template;
    (void)count;

    *key = 2;
    return CKR_OK;
}

static CK_RV test_pkcs11_rd_keygen(CK_SESSION_HANDLE session,
    CK_MECHANISM_PTR mechanism, CK_ATTRIBUTE_PTR pubTmpl, CK_ULONG pubCnt,
    CK_ATTRIBUTE_PTR privTmpl, CK_ULONG privCnt, CK_OBJECT_HANDLE_PTR pub,
    CK_OBJECT_HANDLE_PTR priv)
{
    (void)session;
    (void)mechanism;
    (void)pubTmpl;
    (void)pubCnt;
    (void)privTmpl;
    (void)privCnt;

    *pub = 3;
    *priv = 4;
    return CKR_OK;
}

#if defined(TEST_PKCS11_RD_RSA) || defined(TEST_PKCS11_RD_CERT) || \
    (defined(TEST_PKCS11_RD_ECDH) && defined(WOLF_PRIVATE_KEY_ID)) || \
    defined(TEST_PKCS11_RD_MLKEM_ENC)
    #define TEST_PKCS11_RD_FIND
#endif

#ifdef TEST_PKCS11_RD_FIND
static int test_pkcs11_rd_found = 0;

static CK_RV test_pkcs11_rd_find_init(CK_SESSION_HANDLE session,
    CK_ATTRIBUTE_PTR template, CK_ULONG count)
{
    (void)session;
    (void)template;
    (void)count;

    test_pkcs11_rd_found = 0;
    return CKR_OK;
}

static CK_RV test_pkcs11_rd_find(CK_SESSION_HANDLE session,
    CK_OBJECT_HANDLE_PTR objects, CK_ULONG maxCount, CK_ULONG_PTR count)
{
    (void)session;
    (void)maxCount;

    *count = 0;
    if (!test_pkcs11_rd_found) {
        objects[0] = 5;
        *count = 1;
        test_pkcs11_rd_found = 1;
    }
    return CKR_OK;
}

static CK_RV test_pkcs11_rd_find_final(CK_SESSION_HANDLE session)
{
    (void)session;

    return CKR_OK;
}
#endif

#ifdef TEST_PKCS11_RD_RSA
static CK_RV test_pkcs11_rd_sign_init(CK_SESSION_HANDLE session,
    CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key)
{
    (void)session;
    (void)mechanism;
    (void)key;

    return CKR_MECHANISM_INVALID;
}
#endif

#ifdef TEST_PKCS11_RD_MLKEM_ENC
static CK_RV test_pkcs11_rd_encaps(CK_SESSION_HANDLE session,
    CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE pubKey,
    CK_ATTRIBUTE_PTR template, CK_ULONG count, CK_BYTE_PTR ct,
    CK_ULONG_PTR ctLen, CK_OBJECT_HANDLE_PTR key)
{
    (void)session;
    (void)mechanism;
    (void)pubKey;
    (void)template;
    (void)count;

    XMEMSET(ct, 0, *ctLen);
    *key = 2;
    return CKR_OK;
}
#endif

#ifdef TEST_PKCS11_RD_MLKEM_DEC
static CK_RV test_pkcs11_rd_decaps(CK_SESSION_HANDLE session,
    CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE privKey,
    CK_ATTRIBUTE_PTR template, CK_ULONG count, CK_BYTE_PTR ct,
    CK_ULONG ctLen, CK_OBJECT_HANDLE_PTR key)
{
    (void)session;
    (void)mechanism;
    (void)privKey;
    (void)template;
    (void)count;
    (void)ct;
    (void)ctLen;

    *key = 2;
    return CKR_OK;
}
#endif

static CK_RV test_pkcs11_rd_get_attr(CK_SESSION_HANDLE session,
    CK_OBJECT_HANDLE object, CK_ATTRIBUTE_PTR template, CK_ULONG count)
{
    CK_RV rv = CKR_OK;
    CK_ULONG i;

    (void)session;
    (void)object;

    for (i = 0; i < count; i++) {
        if (template[i].type == CKA_VALUE || template[i].type == CKA_EC_POINT ||
                template[i].type == CKA_MODULUS ||
                template[i].type == CKA_PUBLIC_EXPONENT) {
            if (template[i].pValue == NULL) {
                template[i].ulValueLen = test_pkcs11_rd_len;
                if (template[i].type == CKA_PUBLIC_EXPONENT &&
                        test_pkcs11_rd_exp_len != 0) {
                    template[i].ulValueLen = test_pkcs11_rd_exp_len;
                }
            }
            else {
                if (template[i].ulValueLen < test_pkcs11_rd_len)
                    return CKR_MECHANISM_INVALID;
                if (test_pkcs11_rd_data != NULL) {
                    XMEMCPY(template[i].pValue, test_pkcs11_rd_data,
                        test_pkcs11_rd_len);
                }
                else {
                    XMEMSET(template[i].pValue, 0xa5, test_pkcs11_rd_len);
                }
                template[i].ulValueLen = test_pkcs11_rd_ret_len;
                if (template[i].type == CKA_PUBLIC_EXPONENT)
                    template[i].ulValueLen -= test_pkcs11_rd_exp_short;
                if (template[i].type == CKA_PUBLIC_EXPONENT &&
                        test_pkcs11_rd_exp_len != 0) {
                    template[i].ulValueLen = test_pkcs11_rd_exp_len;
                }
                rv = test_pkcs11_rd_rv;
            }
        }
    #ifdef WOLFSSL_HAVE_MLKEM
        else if (template[i].type == CKA_PARAMETER_SET) {
            *(CK_ML_KEM_PARAMETER_SET_TYPE*)template[i].pValue =
                CKP_ML_KEM_768;
        }
    #endif
        else {
            return CKR_MECHANISM_INVALID;
        }
    }
    return rv;
}
#endif /* TEST_PKCS11_VALUE_READ */
#endif /* HAVE_PKCS11 && !WC_NO_RNG */

int test_wc_Pkcs11_ValueRead(void)
{
    EXPECT_DECLS;
#ifdef TEST_PKCS11_VALUE_READ
    Pkcs11Token token;
    CK_FUNCTION_LIST_3_2 func;
    WC_RNG rng;
#if defined(TEST_PKCS11_RD_ECDH) || defined(TEST_PKCS11_RD_RSA) || \
    defined(TEST_PKCS11_RD_CERT) || defined(TEST_PKCS11_RD_MLKEM_ENC)
    wc_CryptoInfo info;
#endif
#ifdef TEST_PKCS11_RD_ECDH
    static const byte zero[32] = { 0 };
    ecc_key key;
    byte secret[32];
    word32 secretLen = sizeof(secret);
#ifdef WOLF_PRIVATE_KEY_ID
    ecc_key lblKey;
    byte lblSecret[64];
    word32 lblSecretLen = sizeof(lblSecret);
#endif
#endif
#ifdef TEST_PKCS11_RD_ECGEN
    ecc_key genKey;
#endif
#ifdef TEST_PKCS11_RD_RSA
    RsaKey rsa;
    byte in[256];
    byte out[256];
    word32 outLen = sizeof(out);
    int modSz = 0;
#endif
#ifdef TEST_PKCS11_RD_MLDSA
    wc_MlDsaKey dsa;
#endif
#if defined(TEST_PKCS11_RD_MLKEM_GEN) || defined(TEST_PKCS11_RD_MLKEM_ENC) || \
    defined(TEST_PKCS11_RD_MLKEM_DEC)
    MlKemKey kem;
#endif
#if defined(TEST_PKCS11_RD_MLKEM_GEN) && defined(WC_MLKEM_HAVE_NATIVE)
    MlKemKey swKem;
    byte kemPub[WC_ML_KEM_768_PUBLIC_KEY_SIZE];
#endif
#if defined(TEST_PKCS11_RD_MLKEM_ENC) || defined(TEST_PKCS11_RD_MLKEM_DEC)
    static const byte ssZero[WC_ML_KEM_SS_SZ] = { 0 };
    byte ss[WC_ML_KEM_SS_SZ];
#endif
#ifdef TEST_PKCS11_RD_MLKEM_ENC
    byte encCt[WC_ML_KEM_768_CIPHER_TEXT_SIZE];
#endif
#ifdef TEST_PKCS11_RD_MLKEM_DEC
    static const byte ct[WC_ML_KEM_768_CIPHER_TEXT_SIZE] = { 0 };
#endif
#ifdef TEST_PKCS11_RD_CERT
    static const byte certId[] = { 0x01 };
    byte* cert = NULL;
    word32 certSz = 0;
#endif

    XMEMSET(&token, 0, sizeof(token));
    XMEMSET(&func, 0, sizeof(func));
    XMEMSET(&rng, 0, sizeof(rng));
#ifdef TEST_PKCS11_RD_ECGEN
    XMEMSET(&genKey, 0, sizeof(genKey));
#endif
#ifdef TEST_PKCS11_RD_RSA
    XMEMSET(&rsa, 0, sizeof(rsa));
#endif
#ifdef TEST_PKCS11_RD_MLDSA
    XMEMSET(&dsa, 0, sizeof(dsa));
#endif
#if defined(TEST_PKCS11_RD_MLKEM_GEN) || defined(TEST_PKCS11_RD_MLKEM_ENC) || \
    defined(TEST_PKCS11_RD_MLKEM_DEC)
    XMEMSET(&kem, 0, sizeof(kem));
#endif
    func.C_GetMechanismInfo = test_pkcs11_rd_mech_info;
    func.C_CreateObject = test_pkcs11_create_object;
    func.C_DestroyObject = test_pkcs11_destroy_object;
    func.C_DeriveKey = test_pkcs11_rd_derive;
    func.C_GenerateKeyPair = test_pkcs11_rd_keygen;
    func.C_GetAttributeValue = test_pkcs11_rd_get_attr;
#ifdef TEST_PKCS11_RD_FIND
    func.C_FindObjectsInit = test_pkcs11_rd_find_init;
    func.C_FindObjects = test_pkcs11_rd_find;
    func.C_FindObjectsFinal = test_pkcs11_rd_find_final;
#endif
#ifdef TEST_PKCS11_RD_RSA
    func.C_SignInit = test_pkcs11_rd_sign_init;
#endif
#ifdef TEST_PKCS11_RD_MLKEM_ENC
    func.C_EncapsulateKey = test_pkcs11_rd_encaps;
#endif
#ifdef TEST_PKCS11_RD_MLKEM_DEC
    func.C_DecapsulateKey = test_pkcs11_rd_decaps;
#endif
    token.func = (CK_FUNCTION_LIST*)&func;
    token.slotId = 1;
    token.handle = 1;
    token.version = WC_PCKS11VERSION_2_40;
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_CryptoCb_RegisterDevice(TEST_PKCS11_RD_DEVID,
        wc_Pkcs11_CryptoDevCb, &token), 0);

#ifdef TEST_PKCS11_RD_ECDH
    XMEMSET(&info, 0, sizeof(info));
    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(secret, 0xff, sizeof(secret));
    ExpectIntEQ(wc_ecc_init(&key), 0);
    ExpectIntEQ(wc_ecc_make_key(&rng, 32, &key), 0);
    info.algo_type = WC_ALGO_TYPE_PK;
    info.pk.type = WC_PK_TYPE_ECDH;
    info.pk.ecdh.private_key = &key;
    info.pk.ecdh.public_key = &key;
    info.pk.ecdh.out = secret;
    info.pk.ecdh.outlen = &secretLen;
    test_pkcs11_rd_len = sizeof(secret);
    test_pkcs11_rd_ret_len = sizeof(secret);
    test_pkcs11_rd_rv = CKR_MECHANISM_INVALID;
    ExpectIntEQ(wc_Pkcs11_CryptoDevCb(1, &info, &token),
        WC_NO_ERR_TRACE(WC_HW_E));
    ExpectIntEQ(secretLen, sizeof(secret));
    ExpectBufEQ(secret, zero, sizeof(secret));

    XMEMSET(secret, 0xff, sizeof(secret));
    test_pkcs11_rd_ret_len = sizeof(secret) + 1;
    test_pkcs11_rd_rv = CKR_OK;
    ExpectIntEQ(wc_Pkcs11_CryptoDevCb(1, &info, &token),
        WC_NO_ERR_TRACE(WC_HW_E));
    ExpectIntEQ(secretLen, sizeof(secret));
    ExpectBufEQ(secret, zero, sizeof(secret));

    XMEMSET(secret, 0xff, sizeof(secret));
    test_pkcs11_rd_len = sizeof(secret) - 1;
    test_pkcs11_rd_ret_len = sizeof(secret) - 1;
    ExpectIntEQ(wc_Pkcs11_CryptoDevCb(1, &info, &token),
        WC_NO_ERR_TRACE(WC_HW_E));
    ExpectIntEQ(secretLen, sizeof(secret));
    ExpectBufEQ(secret, zero, sizeof(secret));

    XMEMSET(secret, 0xff, sizeof(secret));
    test_pkcs11_rd_ret_len = sizeof(secret);
    ExpectIntEQ(wc_Pkcs11_CryptoDevCb(1, &info, &token),
        WC_NO_ERR_TRACE(WC_HW_E));
    ExpectIntEQ(secretLen, sizeof(secret));
    ExpectBufEQ(secret, zero, sizeof(secret));

    test_pkcs11_rd_len = CK_UNAVAILABLE_INFORMATION;
    ExpectIntEQ(wc_Pkcs11_CryptoDevCb(1, &info, &token),
        WC_NO_ERR_TRACE(WC_HW_E));
    test_pkcs11_rd_len = sizeof(secret) + 1;
    ExpectIntEQ(wc_Pkcs11_CryptoDevCb(1, &info, &token),
        WC_NO_ERR_TRACE(BUFFER_E));
    ExpectIntEQ(secretLen, sizeof(secret));
    test_pkcs11_rd_len = sizeof(secret) - 1;
    test_pkcs11_rd_ret_len = sizeof(secret) - 1;
    secretLen = sizeof(secret) - 1;
    ExpectIntEQ(wc_Pkcs11_CryptoDevCb(1, &info, &token),
        WC_NO_ERR_TRACE(BUFFER_E));
    ExpectIntEQ(secretLen, sizeof(secret) - 1);
    secretLen = sizeof(secret);

    test_pkcs11_rd_len = sizeof(secret);
    test_pkcs11_rd_ret_len = sizeof(secret);
    ExpectIntEQ(wc_Pkcs11_CryptoDevCb(1, &info, &token), 0);
    ExpectIntEQ(secretLen, sizeof(secret));

#ifdef WOLF_PRIVATE_KEY_ID
    XMEMSET(&lblKey, 0, sizeof(lblKey));
    ExpectIntEQ(wc_ecc_init_label(&lblKey, "rd", NULL, INVALID_DEVID), 0);
    info.pk.ecdh.private_key = &lblKey;
    info.pk.ecdh.out = lblSecret;
    info.pk.ecdh.outlen = &lblSecretLen;
    ExpectIntEQ(wc_Pkcs11_CryptoDevCb(1, &info, &token), 0);
    ExpectIntEQ(lblSecretLen, sizeof(secret));
    wc_ecc_free(&lblKey);
#endif
    wc_ecc_free(&key);
#endif

#ifdef TEST_PKCS11_RD_ECGEN
    test_pkcs11_rd_len = 2 + 65;
    test_pkcs11_rd_ret_len = 2 + 64;
    test_pkcs11_rd_rv = CKR_OK;
    ExpectIntEQ(wc_ecc_init_ex(&genKey, NULL, TEST_PKCS11_RD_DEVID), 0);
    ExpectIntEQ(wc_ecc_make_key_ex(&rng, 32, &genKey, ECC_SECP256R1),
        WC_NO_ERR_TRACE(WC_HW_E));
    wc_ecc_free(&genKey);
#endif
#ifdef TEST_PKCS11_RD_RSA
    test_pkcs11_rd_len = sizeof(in);
    test_pkcs11_rd_ret_len = sizeof(in) - 1;
    test_pkcs11_rd_rv = CKR_OK;
    XMEMSET(in, 0, sizeof(in));
    XMEMSET(&info, 0, sizeof(info));
    ExpectIntEQ(wc_InitRsaKey_Label(&rsa, "rd", NULL, TEST_PKCS11_RD_DEVID),
        0);
    info.algo_type = WC_ALGO_TYPE_PK;
    info.pk.type = WC_PK_TYPE_RSA;
    info.pk.rsa.in = in;
    info.pk.rsa.inLen = sizeof(in);
    info.pk.rsa.out = out;
    info.pk.rsa.outLen = &outLen;
    info.pk.rsa.type = RSA_PRIVATE_DECRYPT;
    info.pk.rsa.key = &rsa;
    info.pk.rsa.rng = &rng;
    ExpectIntEQ(wc_Pkcs11_CryptoDevCb(1, &info, &token),
        WC_NO_ERR_TRACE(WC_HW_E));
    ExpectTrue(mp_iszero(&rsa.n));

    test_pkcs11_rd_ret_len = sizeof(in);
    test_pkcs11_rd_exp_short = 1;
    ExpectIntEQ(wc_Pkcs11_CryptoDevCb(1, &info, &token),
        WC_NO_ERR_TRACE(WC_HW_E));
    ExpectTrue(mp_iszero(&rsa.n));
    test_pkcs11_rd_exp_short = 0;
    test_pkcs11_rd_len = RSA_MAX_SIZE / 8 + 1;
    test_pkcs11_rd_ret_len = RSA_MAX_SIZE / 8 + 1;
    ExpectIntEQ(wc_Pkcs11_CryptoDevCb(1, &info, &token),
        WC_NO_ERR_TRACE(WC_HW_E));
    ExpectTrue(mp_iszero(&rsa.n));
    test_pkcs11_rd_len = sizeof(in);
    test_pkcs11_rd_ret_len = sizeof(in);
    test_pkcs11_rd_exp_len = RSA_MAX_SIZE / 8 + 1;
    ExpectIntEQ(wc_Pkcs11_CryptoDevCb(1, &info, &token),
        WC_NO_ERR_TRACE(WC_HW_E));
    ExpectTrue(mp_iszero(&rsa.n));
    test_pkcs11_rd_exp_len = 0;

    test_pkcs11_rd_len = CK_UNAVAILABLE_INFORMATION;
    info.pk.type = WC_PK_TYPE_RSA_GET_SIZE;
    info.pk.rsa_get_size.key = &rsa;
    info.pk.rsa_get_size.keySize = &modSz;
    ExpectIntEQ(wc_Pkcs11_CryptoDevCb(1, &info, &token),
        WC_NO_ERR_TRACE(WC_HW_E));
    ExpectIntEQ(modSz, 0);
    test_pkcs11_rd_len = 0;
    ExpectIntEQ(wc_Pkcs11_CryptoDevCb(1, &info, &token),
        WC_NO_ERR_TRACE(WC_HW_E));
    ExpectIntEQ(modSz, 0);
    if (sizeof(CK_ULONG) > sizeof(word32)) {
        test_pkcs11_rd_len = (CK_ULONG)0xFFFFFFFFUL + 1 + sizeof(in);
        ExpectIntEQ(wc_Pkcs11_CryptoDevCb(1, &info, &token),
            WC_NO_ERR_TRACE(WC_HW_E));
        ExpectIntEQ(modSz, 0);
    }
    test_pkcs11_rd_len = RSA_MAX_SIZE / 8 + 1;
    ExpectIntEQ(wc_Pkcs11_CryptoDevCb(1, &info, &token), 0);
    ExpectIntEQ(modSz, RSA_MAX_SIZE / 8 + 1);
    test_pkcs11_rd_len = sizeof(in);
    ExpectIntEQ(wc_Pkcs11_CryptoDevCb(1, &info, &token), 0);
    ExpectIntEQ(modSz, sizeof(in));

    test_pkcs11_rd_ret_len = sizeof(in);
    XMEMSET(&info, 0, sizeof(info));
    info.algo_type = WC_ALGO_TYPE_PK;
    info.pk.type = WC_PK_TYPE_RSA;
    info.pk.rsa.in = in;
    info.pk.rsa.inLen = sizeof(in);
    info.pk.rsa.out = out;
    info.pk.rsa.outLen = &outLen;
    info.pk.rsa.type = RSA_PRIVATE_DECRYPT;
    info.pk.rsa.key = &rsa;
    info.pk.rsa.rng = &rng;
    ExpectIntEQ(wc_Pkcs11_CryptoDevCb(1, &info, &token),
        WC_NO_ERR_TRACE(WC_HW_E));
    ExpectFalse(mp_iszero(&rsa.n));
    wc_FreeRsaKey(&rsa);
#endif
#ifdef TEST_PKCS11_RD_MLDSA
    test_pkcs11_rd_len = WC_MLDSA_44_PUB_KEY_SIZE;
    test_pkcs11_rd_ret_len = WC_MLDSA_44_PUB_KEY_SIZE - 1;
    test_pkcs11_rd_rv = CKR_OK;
    ExpectIntEQ(wc_MlDsaKey_Init(&dsa, NULL, TEST_PKCS11_RD_DEVID), 0);
    ExpectIntEQ(wc_MlDsaKey_SetParams(&dsa, WC_ML_DSA_44), 0);
    ExpectIntEQ(wc_MlDsaKey_MakeKey(&dsa, &rng), WC_NO_ERR_TRACE(WC_HW_E));
    test_pkcs11_rd_len = CK_UNAVAILABLE_INFORMATION;
    ExpectIntEQ(wc_MlDsaKey_MakeKey(&dsa, &rng), WC_NO_ERR_TRACE(WC_HW_E));
    test_pkcs11_rd_len = MLDSA_MAX_PUB_KEY_SIZE + 1;
    test_pkcs11_rd_ret_len = MLDSA_MAX_PUB_KEY_SIZE + 1;
    ExpectIntEQ(wc_MlDsaKey_MakeKey(&dsa, &rng), WC_NO_ERR_TRACE(WC_HW_E));
    test_pkcs11_rd_len = WC_MLDSA_44_PUB_KEY_SIZE;
    test_pkcs11_rd_ret_len = WC_MLDSA_44_PUB_KEY_SIZE;
    ExpectIntEQ(wc_MlDsaKey_MakeKey(&dsa, &rng), 0);
    wc_MlDsaKey_Free(&dsa);
#endif
#ifdef TEST_PKCS11_RD_MLKEM_GEN
    test_pkcs11_rd_len = WC_ML_KEM_768_PUBLIC_KEY_SIZE;
    test_pkcs11_rd_ret_len = WC_ML_KEM_768_PUBLIC_KEY_SIZE - 1;
    test_pkcs11_rd_rv = CKR_OK;
    ExpectIntEQ(wc_MlKemKey_Init(&kem, WC_ML_KEM_768, NULL,
        TEST_PKCS11_RD_DEVID), 0);
    ExpectIntEQ(wc_MlKemKey_MakeKey(&kem, &rng), WC_NO_ERR_TRACE(WC_HW_E));
    test_pkcs11_rd_len = CK_UNAVAILABLE_INFORMATION;
    ExpectIntEQ(wc_MlKemKey_MakeKey(&kem, &rng), WC_NO_ERR_TRACE(WC_HW_E));
    test_pkcs11_rd_len = WC_ML_KEM_768_PUBLIC_KEY_SIZE + 1;
    test_pkcs11_rd_ret_len = WC_ML_KEM_768_PUBLIC_KEY_SIZE + 1;
    ExpectIntEQ(wc_MlKemKey_MakeKey(&kem, &rng), WC_NO_ERR_TRACE(WC_HW_E));
#ifdef WC_MLKEM_HAVE_NATIVE
    XMEMSET(&swKem, 0, sizeof(swKem));
    ExpectIntEQ(wc_MlKemKey_Init(&swKem, WC_ML_KEM_768, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_MlKemKey_MakeKey(&swKem, &rng), 0);
    ExpectIntEQ(wc_MlKemKey_EncodePublicKey(&swKem, kemPub, sizeof(kemPub)),
        0);
    wc_MlKemKey_Free(&swKem);
    test_pkcs11_rd_len = sizeof(kemPub);
    test_pkcs11_rd_ret_len = sizeof(kemPub);
    test_pkcs11_rd_data = kemPub;
    ExpectIntEQ(wc_MlKemKey_MakeKey(&kem, &rng), 0);
    test_pkcs11_rd_data = NULL;
#endif
    wc_MlKemKey_Free(&kem);
#endif

#ifdef TEST_PKCS11_RD_CERT
    test_pkcs11_rd_len = 100;
    test_pkcs11_rd_ret_len = 99;
    test_pkcs11_rd_rv = CKR_OK;
    XMEMSET(&info, 0, sizeof(info));
    info.algo_type = WC_ALGO_TYPE_CERT;
    info.cert.id = certId;
    info.cert.idLen = sizeof(certId);
    info.cert.certDataOut = &cert;
    info.cert.certSz = &certSz;
    ExpectIntEQ(wc_Pkcs11_CryptoDevCb(1, &info, &token),
        WC_NO_ERR_TRACE(WC_HW_E));
    ExpectNull(cert);
    test_pkcs11_rd_ret_len = 100;
    ExpectIntEQ(wc_Pkcs11_CryptoDevCb(1, &info, &token), 0);
    ExpectNotNull(cert);
    ExpectIntEQ(certSz, 100);
    XFREE(cert, NULL, DYNAMIC_TYPE_CERT);
#endif

#ifdef TEST_PKCS11_RD_MLKEM_ENC
    token.version = WC_PCKS11VERSION_3_2;
    test_pkcs11_rd_len = WC_ML_KEM_SS_SZ - 1;
    test_pkcs11_rd_ret_len = WC_ML_KEM_SS_SZ - 1;
    test_pkcs11_rd_rv = CKR_OK;
    XMEMSET(ss, 0xff, sizeof(ss));
    ExpectIntEQ(wc_MlKemKey_Init_Label(&kem, WC_ML_KEM_768, "rd", NULL,
        TEST_PKCS11_RD_DEVID), 0);
    XMEMSET(&info, 0, sizeof(info));
    info.algo_type = WC_ALGO_TYPE_PK;
    info.pk.type = WC_PK_TYPE_PQC_KEM_ENCAPS;
    info.pk.pqc_encaps.ciphertext = encCt;
    info.pk.pqc_encaps.ciphertextLen = sizeof(encCt);
    info.pk.pqc_encaps.sharedSecret = ss;
    info.pk.pqc_encaps.sharedSecretLen = sizeof(ss);
    info.pk.pqc_encaps.rng = &rng;
    info.pk.pqc_encaps.key = &kem;
    info.pk.pqc_encaps.type = WC_PQC_KEM_TYPE_MLKEM;
    ExpectIntEQ(wc_Pkcs11_CryptoDevCb(1, &info, &token),
        WC_NO_ERR_TRACE(WC_HW_E));
    ExpectBufEQ(ss, ssZero, sizeof(ss));
    test_pkcs11_rd_len = WC_ML_KEM_SS_SZ;
    test_pkcs11_rd_ret_len = WC_ML_KEM_SS_SZ;
    ExpectIntEQ(wc_Pkcs11_CryptoDevCb(1, &info, &token), 0);
    ExpectIntEQ(ss[0], 0xa5);
    ExpectIntEQ(ss[WC_ML_KEM_SS_SZ - 1], 0xa5);
    wc_MlKemKey_Free(&kem);
#endif

#ifdef TEST_PKCS11_RD_MLKEM_DEC
    token.version = WC_PCKS11VERSION_3_2;
    test_pkcs11_rd_len = WC_ML_KEM_SS_SZ - 1;
    test_pkcs11_rd_ret_len = WC_ML_KEM_SS_SZ - 1;
    test_pkcs11_rd_rv = CKR_OK;
    XMEMSET(ss, 0xff, sizeof(ss));
    ExpectIntEQ(wc_MlKemKey_Init(&kem, WC_ML_KEM_768, NULL,
        TEST_PKCS11_RD_DEVID), 0);
    kem.devCtx = (void*)(wc_ptr_t)4;
    ExpectIntEQ(wc_MlKemKey_Decapsulate(&kem, ss, ct, sizeof(ct)),
        WC_NO_ERR_TRACE(WC_HW_E));
    ExpectBufEQ(ss, ssZero, sizeof(ss));
    test_pkcs11_rd_len = WC_ML_KEM_SS_SZ;
    test_pkcs11_rd_ret_len = WC_ML_KEM_SS_SZ;
    ExpectIntEQ(wc_MlKemKey_Decapsulate(&kem, ss, ct, sizeof(ct)), 0);
    ExpectIntEQ(ss[0], 0xa5);
    ExpectIntEQ(ss[WC_ML_KEM_SS_SZ - 1], 0xa5);
    kem.devCtx = NULL;
    wc_MlKemKey_Free(&kem);
#endif

    wc_CryptoCb_UnRegisterDevice(TEST_PKCS11_RD_DEVID);
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();
}

int test_wc_Pkcs11_EcdsaSigDecode(void)
{
    EXPECT_DECLS;
#ifdef TEST_PKCS11_ECDSA
    static const byte emptyR[] = {
        0x30, 0x05, 0x02, 0x00, 0x02, 0x01, 0x01
    };
    static const byte emptyS[] = {
        0x30, 0x05, 0x02, 0x01, 0x01, 0x02, 0x00
    };
    static const byte hash[] = { 0x00 };
    byte oversizedR[40];
    byte oversizedS[40];
    byte paddedSig[72];
    byte expectedSig[64];
    Pkcs11Token token;
    CK_FUNCTION_LIST func;
    wc_CryptoInfo info;
    ecc_key key;
#ifdef WOLF_PRIVATE_KEY_ID
    ecc_key idKey;
    ecc_key lblKey;
    unsigned char id[] = { 0x01 };
#endif
    WC_RNG rng;
    int ret;
    int res = 0;
    int haveKey = 0;
    int haveRng = 0;

    XMEMSET(&token, 0, sizeof(token));
    XMEMSET(&func, 0, sizeof(func));
    XMEMSET(&info, 0, sizeof(info));
    XMEMSET(&key, 0, sizeof(key));
#ifdef WOLF_PRIVATE_KEY_ID
    XMEMSET(&idKey, 0, sizeof(idKey));
    XMEMSET(&lblKey, 0, sizeof(lblKey));
#endif
    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(oversizedR, 0, sizeof(oversizedR));
    oversizedR[0] = 0x30;
    oversizedR[1] = 0x26;
    oversizedR[2] = 0x02;
    oversizedR[3] = 0x21;
    oversizedR[4] = 0x01;
    oversizedR[37] = 0x02;
    oversizedR[38] = 0x01;
    oversizedR[39] = 0x01;
    XMEMSET(oversizedS, 0, sizeof(oversizedS));
    oversizedS[0] = 0x30;
    oversizedS[1] = 0x26;
    oversizedS[2] = 0x02;
    oversizedS[3] = 0x01;
    oversizedS[4] = 0x01;
    oversizedS[5] = 0x02;
    oversizedS[6] = 0x21;
    oversizedS[7] = 0x01;
    XMEMSET(paddedSig, 0, sizeof(paddedSig));
    paddedSig[0] = 0x30;
    paddedSig[1] = 0x46;
    paddedSig[2] = 0x02;
    paddedSig[3] = 0x21;
    paddedSig[5] = 0x80;
    paddedSig[37] = 0x02;
    paddedSig[38] = 0x21;
    paddedSig[40] = 0x81;
    XMEMSET(expectedSig, 0, sizeof(expectedSig));
    expectedSig[0] = 0x80;
    expectedSig[32] = 0x81;

    func.C_GetMechanismInfo = test_pkcs11_get_mechanism_info;
    func.C_CreateObject = test_pkcs11_create_object;
    func.C_DestroyObject = test_pkcs11_destroy_object;
    func.C_VerifyInit = test_pkcs11_verify_init;
    func.C_Verify = test_pkcs11_verify;
#ifdef WOLF_PRIVATE_KEY_ID
    func.C_FindObjectsInit = test_pkcs11_find_objects_init;
    func.C_FindObjects = test_pkcs11_find_objects;
    func.C_FindObjectsFinal = test_pkcs11_find_objects_final;
    func.C_GetAttributeValue = test_pkcs11_get_attribute_value;
#endif
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
    if (ret == WC_NO_ERR_TRACE(WC_PENDING_E))
        ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    ExpectIntEQ(ret, 0);

    info.algo_type = WC_ALGO_TYPE_PK;
    info.pk.type = WC_PK_TYPE_ECDSA_VERIFY;
    info.pk.eccverify.hash = hash;
    info.pk.eccverify.hashlen = sizeof(hash);
    info.pk.eccverify.key = &key;
    info.pk.eccverify.res = &res;
    test_pkcs11_expected_sig = NULL;
    test_pkcs11_expected_sig_len = 0;

    if (ret == 0) {
        info.pk.eccverify.sig = emptyR;
        info.pk.eccverify.siglen = sizeof(emptyR);
        res = 0;
        test_pkcs11_verify_init_calls = 0;
        test_pkcs11_verify_calls = 0;
        ExpectIntEQ(wc_Pkcs11_CryptoDevCb(1, &info, &token),
            WC_NO_ERR_TRACE(ASN_PARSE_E));
        ExpectIntEQ(test_pkcs11_verify_init_calls, 0);
        ExpectIntEQ(test_pkcs11_verify_calls, 0);
    }

    if (ret == 0) {
        info.pk.eccverify.sig = emptyS;
        info.pk.eccverify.siglen = sizeof(emptyS);
        res = 0;
        test_pkcs11_verify_init_calls = 0;
        test_pkcs11_verify_calls = 0;
        ExpectIntEQ(wc_Pkcs11_CryptoDevCb(1, &info, &token),
            WC_NO_ERR_TRACE(ASN_PARSE_E));
        ExpectIntEQ(test_pkcs11_verify_init_calls, 0);
        ExpectIntEQ(test_pkcs11_verify_calls, 0);
    }

    if (ret == 0) {
        info.pk.eccverify.sig = oversizedR;
        info.pk.eccverify.siglen = sizeof(oversizedR);
        res = 0;
        test_pkcs11_verify_init_calls = 0;
        test_pkcs11_verify_calls = 0;
        ExpectIntEQ(wc_Pkcs11_CryptoDevCb(1, &info, &token),
            WC_NO_ERR_TRACE(ASN_PARSE_E));
        ExpectIntEQ(test_pkcs11_verify_init_calls, 0);
        ExpectIntEQ(test_pkcs11_verify_calls, 0);
    }

    if (ret == 0) {
        info.pk.eccverify.sig = oversizedS;
        info.pk.eccverify.siglen = sizeof(oversizedS);
        res = 0;
        test_pkcs11_verify_init_calls = 0;
        test_pkcs11_verify_calls = 0;
        ExpectIntEQ(wc_Pkcs11_CryptoDevCb(1, &info, &token),
            WC_NO_ERR_TRACE(ASN_PARSE_E));
        ExpectIntEQ(test_pkcs11_verify_init_calls, 0);
        ExpectIntEQ(test_pkcs11_verify_calls, 0);
    }

    if (ret == 0) {
        info.pk.eccverify.sig = paddedSig;
        info.pk.eccverify.siglen = sizeof(paddedSig);
        res = 0;
        test_pkcs11_verify_init_calls = 0;
        test_pkcs11_verify_calls = 0;
        test_pkcs11_expected_sig = expectedSig;
        test_pkcs11_expected_sig_len = sizeof(expectedSig);
        ExpectIntEQ(wc_Pkcs11_CryptoDevCb(1, &info, &token), 0);
        ExpectIntEQ(res, 1);
        ExpectIntEQ(test_pkcs11_verify_init_calls, 1);
        ExpectIntEQ(test_pkcs11_verify_calls, 1);
    }

#ifdef WOLF_PRIVATE_KEY_ID
    if (ret == 0) {
        ExpectIntEQ(wc_ecc_init_id(&idKey, id, (int)sizeof(id), NULL,
            INVALID_DEVID), 0);
        info.pk.eccverify.key = &idKey;
        test_pkcs11_params_tag = 0x04;
        ExpectIntEQ(wc_Pkcs11_CryptoDevCb(1, &info, &token),
            WC_NO_ERR_TRACE(WC_HW_E));
        test_pkcs11_params_tag = 0x06;
        test_pkcs11_params_oid_len = 0x07;
        ExpectIntEQ(wc_Pkcs11_CryptoDevCb(1, &info, &token),
            WC_NO_ERR_TRACE(WC_HW_E));
        test_pkcs11_params_oid_len = 0x08;
        test_pkcs11_params_sz = 1;
        ExpectIntEQ(wc_Pkcs11_CryptoDevCb(1, &info, &token),
            WC_NO_ERR_TRACE(WC_HW_E));
        test_pkcs11_params_sz = 17;
        ExpectIntEQ(wc_Pkcs11_CryptoDevCb(1, &info, &token),
            WC_NO_ERR_TRACE(WC_HW_E));
        test_pkcs11_params_sz = 10;
        res = 0;
        ExpectIntEQ(wc_Pkcs11_CryptoDevCb(1, &info, &token), 0);
        ExpectIntEQ(res, 1);
        ExpectIntEQ(test_pkcs11_verify_key, TEST_PKCS11_PUB_OBJ);
    #ifdef WC_PKCS11_FIND_WITH_ID_ONLY
        test_pkcs11_class_len = sizeof(CK_OBJECT_CLASS) - 1;
        ExpectIntEQ(wc_Pkcs11_CryptoDevCb(1, &info, &token),
            WC_NO_ERR_TRACE(WC_HW_E));
        test_pkcs11_class_len = sizeof(CK_OBJECT_CLASS);
    #endif
        wc_ecc_free(&idKey);
    }

    if (ret == 0) {
        ExpectIntEQ(wc_ecc_init_label(&lblKey, "lbl", NULL, INVALID_DEVID),
            0);
        info.pk.eccverify.key = &lblKey;
        res = 0;
        test_pkcs11_verify_key = 0;
        ExpectIntEQ(wc_Pkcs11_CryptoDevCb(1, &info, &token), 0);
        ExpectIntEQ(res, 1);
        ExpectIntEQ(test_pkcs11_verify_key, TEST_PKCS11_PUB_OBJ);
        wc_ecc_free(&lblKey);
    }
#endif

    test_pkcs11_expected_sig = NULL;
    test_pkcs11_expected_sig_len = 0;
    if (haveKey)
        wc_ecc_free(&key);
    if (haveRng)
        DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif

    return EXPECT_RESULT();
}

#ifdef TEST_PKCS11_ECDSA
#if !defined(NO_RSA) && !defined(NO_PKCS11_RSA) && defined(WOLFSSL_KEY_GEN)
    #define TEST_PKCS11_RSA_KEYGEN
#endif
#if defined(HAVE_ECC) && !defined(NO_PKCS11_ECC)
    #define TEST_PKCS11_ECC
#endif
#if defined(TEST_PKCS11_ECC) && !defined(NO_PKCS11_EC_KEYGEN) && \
    defined(HAVE_ECC_KEY_EXPORT) && defined(HAVE_ECC_DHE)
    #define TEST_PKCS11_EC_KEYGEN
#endif

#define TEST_PKCS11_MAX_OBJS    8
#define TEST_PKCS11_MAX_ID_LEN  32
#define TEST_CKR_GENERAL_ERROR  ((CK_RV)0x00000005UL)

typedef struct TestPkcs11Obj {
    int             used;
    CK_OBJECT_CLASS cls;
    CK_KEY_TYPE     keyType;
    CK_BBOOL        onToken;
    byte            id[TEST_PKCS11_MAX_ID_LEN];
    CK_ULONG        idLen;
    char            label[TEST_PKCS11_MAX_ID_LEN];
    CK_ULONG        labelLen;
    CK_BBOOL        sign;
    CK_BBOOL        derive;
    CK_BBOOL        decrypt;
} TestPkcs11Obj;

static const byte test_pkcs11_modulus[256] = { 0xc0, 0x01 };
static const byte test_pkcs11_exponent[3] = { 0x01, 0x00, 0x01 };
static byte       test_pkcs11_keygen_exp[8];
static CK_ULONG   test_pkcs11_keygen_exp_len = 0;

static TestPkcs11Obj test_pkcs11_objs[TEST_PKCS11_MAX_OBJS];
static TestPkcs11Obj test_pkcs11_find;
static CK_ULONG      test_pkcs11_find_mask;
static CK_ULONG      test_pkcs11_find_next;
static int           test_pkcs11_destroy_calls = 0;
static int           test_pkcs11_find_calls = 0;
static int           test_pkcs11_modulus_reads = 0;
static int           test_pkcs11_fail_pub_create = 0;
static int           test_pkcs11_no_ecdh = 0;
static int           test_pkcs11_no_ecdsa = 0;
static int           test_pkcs11_ecdsa_verify_only = 0;
static int           test_pkcs11_fail_modulus = 0;
static int           test_pkcs11_fail_keygen = 0;
static byte          test_pkcs11_ec_point[2 + 65];
static TestPkcs11Obj test_pkcs11_last_priv;
static const byte    test_pkcs11_secret[32] = { 0x5a, 0x5a };

#define TEST_PKCS11_FIND_CLASS  0x01
#define TEST_PKCS11_FIND_TYPE   0x02
#define TEST_PKCS11_FIND_TOKEN  0x04
#define TEST_PKCS11_FIND_ID     0x08
#define TEST_PKCS11_FIND_LABEL  0x10

static void test_pkcs11_reset(void)
{
    XMEMSET(test_pkcs11_objs, 0, sizeof(test_pkcs11_objs));
    test_pkcs11_destroy_calls = 0;
    test_pkcs11_fail_pub_create = 0;
    test_pkcs11_fail_modulus = 0;
    test_pkcs11_fail_keygen = 0;
}

static TestPkcs11Obj* test_pkcs11_obj(CK_OBJECT_HANDLE h)
{
    if (h == 0 || h > TEST_PKCS11_MAX_OBJS || !test_pkcs11_objs[h - 1].used)
        return NULL;
    return &test_pkcs11_objs[h - 1];
}

#if defined(TEST_PKCS11_ECC) || defined(TEST_PKCS11_RSA_KEYGEN)
static int test_pkcs11_count(CK_BBOOL onToken)
{
    int i;
    int cnt = 0;

    for (i = 0; i < TEST_PKCS11_MAX_OBJS; i++) {
        if (test_pkcs11_objs[i].used && test_pkcs11_objs[i].onToken == onToken)
            cnt++;
    }
    return cnt;
}
#endif

/* Applies the template to obj and returns a TEST_PKCS11_FIND_* mask. */
static CK_ULONG test_pkcs11_apply(TestPkcs11Obj* obj, CK_ATTRIBUTE_PTR tmpl,
    CK_ULONG cnt)
{
    CK_ULONG i;
    CK_ULONG mask = 0;

    for (i = 0; i < cnt; i++) {
        if (tmpl[i].type == CKA_CLASS) {
            obj->cls = *(CK_OBJECT_CLASS*)tmpl[i].pValue;
            mask |= TEST_PKCS11_FIND_CLASS;
        }
        else if (tmpl[i].type == CKA_KEY_TYPE) {
            obj->keyType = *(CK_KEY_TYPE*)tmpl[i].pValue;
            mask |= TEST_PKCS11_FIND_TYPE;
        }
        else if (tmpl[i].type == CKA_TOKEN) {
            obj->onToken = *(CK_BBOOL*)tmpl[i].pValue;
            mask |= TEST_PKCS11_FIND_TOKEN;
        }
        else if (tmpl[i].type == CKA_ID &&
                 tmpl[i].ulValueLen <= TEST_PKCS11_MAX_ID_LEN) {
            XMEMCPY(obj->id, tmpl[i].pValue, tmpl[i].ulValueLen);
            obj->idLen = tmpl[i].ulValueLen;
            mask |= TEST_PKCS11_FIND_ID;
        }
        else if (tmpl[i].type == CKA_SIGN) {
            obj->sign = *(CK_BBOOL*)tmpl[i].pValue;
        }
        else if (tmpl[i].type == CKA_DERIVE) {
            obj->derive = *(CK_BBOOL*)tmpl[i].pValue;
        }
        else if (tmpl[i].type == CKA_DECRYPT) {
            obj->decrypt = *(CK_BBOOL*)tmpl[i].pValue;
        }
        else if (tmpl[i].type == CKA_LABEL &&
                 tmpl[i].ulValueLen <= TEST_PKCS11_MAX_ID_LEN) {
            XMEMCPY(obj->label, tmpl[i].pValue, tmpl[i].ulValueLen);
            obj->labelLen = tmpl[i].ulValueLen;
            mask |= TEST_PKCS11_FIND_LABEL;
        }
    }
    return mask;
}

static CK_RV test_pkcs11_store_create(CK_SESSION_HANDLE session,
    CK_ATTRIBUTE_PTR tmpl, CK_ULONG cnt, CK_OBJECT_HANDLE_PTR object)
{
    CK_ULONG i;

    (void)session;

    for (i = 0; i < TEST_PKCS11_MAX_OBJS; i++) {
        if (!test_pkcs11_objs[i].used)
            break;
    }
    if (i == TEST_PKCS11_MAX_OBJS)
        return TEST_CKR_GENERAL_ERROR;

    XMEMSET(&test_pkcs11_objs[i], 0, sizeof(test_pkcs11_objs[i]));
    (void)test_pkcs11_apply(&test_pkcs11_objs[i], tmpl, cnt);
    if (test_pkcs11_fail_pub_create &&
            test_pkcs11_objs[i].cls == CKO_PUBLIC_KEY)
        return TEST_CKR_GENERAL_ERROR;
    test_pkcs11_objs[i].used = 1;
    if (test_pkcs11_objs[i].cls == CKO_PRIVATE_KEY)
        test_pkcs11_last_priv = test_pkcs11_objs[i];
    *object = i + 1;
    return CKR_OK;
}

static CK_RV test_pkcs11_store_destroy(CK_SESSION_HANDLE session,
    CK_OBJECT_HANDLE object)
{
    TestPkcs11Obj* obj = test_pkcs11_obj(object);

    (void)session;

    test_pkcs11_destroy_calls++;
    if (obj == NULL)
        return TEST_CKR_GENERAL_ERROR;
    obj->used = 0;
    return CKR_OK;
}

static CK_RV test_pkcs11_store_get_attr(CK_SESSION_HANDLE session,
    CK_OBJECT_HANDLE object, CK_ATTRIBUTE_PTR tmpl, CK_ULONG cnt)
{
    TestPkcs11Obj* obj = test_pkcs11_obj(object);
    CK_ULONG i;

    (void)session;

    if (obj == NULL)
        return TEST_CKR_GENERAL_ERROR;
    for (i = 0; i < cnt; i++) {
        const byte* val = NULL;
        CK_ULONG    len = 0;

        if (tmpl[i].type == CKA_MODULUS)
            test_pkcs11_modulus_reads++;
        if (tmpl[i].type == CKA_TOKEN) {
            val = &obj->onToken;
            len = sizeof(obj->onToken);
        }
        else if (tmpl[i].type == CKA_CLASS) {
            val = (const byte*)&obj->cls;
            len = sizeof(obj->cls);
        }
        else if (tmpl[i].type == CKA_KEY_TYPE) {
            val = (const byte*)&obj->keyType;
            len = sizeof(obj->keyType);
        }
        else if (tmpl[i].type == CKA_MODULUS && test_pkcs11_fail_modulus) {
            return TEST_CKR_GENERAL_ERROR;
        }
        else if (tmpl[i].type == CKA_MODULUS) {
            val = test_pkcs11_modulus;
            len = sizeof(test_pkcs11_modulus);
        }
        else if (tmpl[i].type == CKA_PUBLIC_EXPONENT) {
            val = test_pkcs11_exponent;
            len = sizeof(test_pkcs11_exponent);
        }
        else if (tmpl[i].type == CKA_EC_POINT) {
            val = test_pkcs11_ec_point;
            len = sizeof(test_pkcs11_ec_point);
        }
        else if (tmpl[i].type == CKA_VALUE) {
            val = test_pkcs11_secret;
            len = sizeof(test_pkcs11_secret);
        }
        else {
            return TEST_CKR_GENERAL_ERROR;
        }
        if (tmpl[i].pValue != NULL) {
            if (tmpl[i].ulValueLen < len)
                return TEST_CKR_GENERAL_ERROR;
            XMEMCPY(tmpl[i].pValue, val, len);
        }
        tmpl[i].ulValueLen = len;
    }
    return CKR_OK;
}

static int test_pkcs11_matches(const TestPkcs11Obj* obj)
{
    const TestPkcs11Obj* f = &test_pkcs11_find;
    CK_ULONG m = test_pkcs11_find_mask;

    return obj->used &&
        (!(m & TEST_PKCS11_FIND_CLASS) || obj->cls == f->cls) &&
        (!(m & TEST_PKCS11_FIND_TYPE) || obj->keyType == f->keyType) &&
        (!(m & TEST_PKCS11_FIND_TOKEN) || obj->onToken == f->onToken) &&
        (!(m & TEST_PKCS11_FIND_ID) || (obj->idLen == f->idLen &&
            XMEMCMP(obj->id, f->id, f->idLen) == 0)) &&
        (!(m & TEST_PKCS11_FIND_LABEL) || (obj->labelLen == f->labelLen &&
            XMEMCMP(obj->label, f->label, f->labelLen) == 0));
}

static CK_RV test_pkcs11_store_find_init(CK_SESSION_HANDLE session,
    CK_ATTRIBUTE_PTR tmpl, CK_ULONG cnt)
{
    (void)session;

    test_pkcs11_find_calls++;
    XMEMSET(&test_pkcs11_find, 0, sizeof(test_pkcs11_find));
    test_pkcs11_find_mask = test_pkcs11_apply(&test_pkcs11_find, tmpl, cnt);
    test_pkcs11_find_next = 0;
    return CKR_OK;
}

static CK_RV test_pkcs11_store_find(CK_SESSION_HANDLE session,
    CK_OBJECT_HANDLE_PTR objects, CK_ULONG max, CK_ULONG_PTR cnt)
{
    (void)session;

    *cnt = 0;
    while (*cnt < max && test_pkcs11_find_next < TEST_PKCS11_MAX_OBJS) {
        if (test_pkcs11_matches(&test_pkcs11_objs[test_pkcs11_find_next]))
            objects[(*cnt)++] = test_pkcs11_find_next + 1;
        test_pkcs11_find_next++;
    }
    return CKR_OK;
}

static CK_RV test_pkcs11_store_find_final(CK_SESSION_HANDLE session)
{
    (void)session;

    return CKR_OK;
}

static CK_RV test_pkcs11_store_mech_info(CK_SLOT_ID slotId,
    CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR info)
{
    (void)slotId;

    if (info == NULL || (type != CKM_ECDSA && type != CKM_RSA_X_509 &&
            type != CKM_EC_KEY_PAIR_GEN && type != CKM_ECDH1_DERIVE &&
            type != CKM_RSA_PKCS_KEY_PAIR_GEN) ||
            (type == CKM_ECDH1_DERIVE && test_pkcs11_no_ecdh) ||
            (type == CKM_ECDSA && test_pkcs11_no_ecdsa))
        return CKR_MECHANISM_INVALID;

    XMEMSET(info, 0, sizeof(*info));
    info->flags = CKF_SIGN | CKF_VERIFY | CKF_DECRYPT;
    /* Some modules leave CKF_DERIVE out for CKM_ECDH1_DERIVE. */
    if (type == CKM_ECDH1_DERIVE)
        info->flags = 0;
    else if (type == CKM_ECDSA && test_pkcs11_ecdsa_verify_only)
        info->flags = CKF_VERIFY;
    return CKR_OK;
}

static CK_RV test_pkcs11_store_decrypt_init(CK_SESSION_HANDLE session,
    CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key)
{
    (void)session;
    (void)mechanism;

    return test_pkcs11_obj(key) != NULL ? CKR_OK : TEST_CKR_GENERAL_ERROR;
}

static CK_RV test_pkcs11_store_decrypt(CK_SESSION_HANDLE session,
    CK_BYTE_PTR in, CK_ULONG inLen, CK_BYTE_PTR out, CK_ULONG_PTR outLen)
{
    (void)session;
    (void)in;

    if (*outLen < inLen)
        return TEST_CKR_GENERAL_ERROR;
    XMEMSET(out, 0, inLen);
    *outLen = inLen;
    return CKR_OK;
}

static CK_RV test_pkcs11_store_sign(CK_SESSION_HANDLE session,
    CK_BYTE_PTR data, CK_ULONG dataLen, CK_BYTE_PTR sig, CK_ULONG_PTR sigLen)
{
    (void)session;
    (void)data;
    (void)dataLen;

    if (*sigLen < 64)
        return TEST_CKR_GENERAL_ERROR;
    XMEMSET(sig, 0x01, 64);
    *sigLen = 64;
    return CKR_OK;
}

static CK_RV test_pkcs11_store_derive(CK_SESSION_HANDLE session,
    CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE base, CK_ATTRIBUTE_PTR tmpl,
    CK_ULONG cnt, CK_OBJECT_HANDLE_PTR key)
{
    (void)mechanism;

    if (test_pkcs11_obj(base) == NULL)
        return TEST_CKR_GENERAL_ERROR;
    return test_pkcs11_store_create(session, tmpl, cnt, key);
}

static CK_RV test_pkcs11_store_keygen(CK_SESSION_HANDLE session,
    CK_MECHANISM_PTR mechanism, CK_ATTRIBUTE_PTR pubTmpl, CK_ULONG pubCnt,
    CK_ATTRIBUTE_PTR privTmpl, CK_ULONG privCnt, CK_OBJECT_HANDLE_PTR pub,
    CK_OBJECT_HANDLE_PTR priv)
{
    CK_RV rv;
    CK_KEY_TYPE keyType = CKK_EC;
    CK_ULONG i;

    if (test_pkcs11_fail_keygen)
        return TEST_CKR_GENERAL_ERROR;
    if (mechanism->mechanism == CKM_RSA_PKCS_KEY_PAIR_GEN)
        keyType = CKK_RSA;
    for (i = 0; i < pubCnt; i++) {
        if (pubTmpl[i].type == CKA_PUBLIC_EXPONENT &&
                pubTmpl[i].ulValueLen <= sizeof(test_pkcs11_keygen_exp)) {
            XMEMCPY(test_pkcs11_keygen_exp, pubTmpl[i].pValue,
                pubTmpl[i].ulValueLen);
            test_pkcs11_keygen_exp_len = pubTmpl[i].ulValueLen;
        }
    }
    rv = test_pkcs11_store_create(session, pubTmpl, pubCnt, pub);
    if (rv == CKR_OK) {
        test_pkcs11_objs[*pub - 1].cls = CKO_PUBLIC_KEY;
        test_pkcs11_objs[*pub - 1].keyType = keyType;
        rv = test_pkcs11_store_create(session, privTmpl, privCnt, priv);
    }
    if (rv == CKR_OK) {
        test_pkcs11_objs[*priv - 1].cls = CKO_PRIVATE_KEY;
        test_pkcs11_objs[*priv - 1].keyType = keyType;
    }
    return rv;
}

static void test_pkcs11_store_setup(Pkcs11Token* token, CK_FUNCTION_LIST* func)
{
    XMEMSET(token, 0, sizeof(*token));
    XMEMSET(func, 0, sizeof(*func));
    func->C_GetMechanismInfo = test_pkcs11_store_mech_info;
    func->C_CreateObject = test_pkcs11_store_create;
    func->C_DestroyObject = test_pkcs11_store_destroy;
    func->C_GetAttributeValue = test_pkcs11_store_get_attr;
    func->C_FindObjectsInit = test_pkcs11_store_find_init;
    func->C_FindObjects = test_pkcs11_store_find;
    func->C_FindObjectsFinal = test_pkcs11_store_find_final;
    func->C_GenerateKeyPair = test_pkcs11_store_keygen;
    func->C_DecryptInit = test_pkcs11_store_decrypt_init;
    func->C_Decrypt = test_pkcs11_store_decrypt;
    func->C_SignInit = test_pkcs11_store_decrypt_init;
    func->C_Sign = test_pkcs11_store_sign;
    func->C_DeriveKey = test_pkcs11_store_derive;
    token->func = func;
    token->slotId = 1;
    token->handle = 1;
    token->version = WC_PCKS11VERSION_2_40;
    test_pkcs11_no_ecdh = 0;
    test_pkcs11_no_ecdsa = 0;
    test_pkcs11_ecdsa_verify_only = 0;
    test_pkcs11_reset();
}

#ifdef TEST_PKCS11_ECC
static int test_pkcs11_free_ecc(Pkcs11Token* token, ecc_key* key)
{
    wc_CryptoInfo info;

    XMEMSET(&info, 0, sizeof(info));
    info.algo_type = WC_ALGO_TYPE_FREE;
    info.free.algo = WC_ALGO_TYPE_PK;
    info.free.type = WC_PK_TYPE_EC_KEYGEN;
    info.free.obj = key;
    return wc_Pkcs11_CryptoDevCb(1, &info, token);
}
#endif

int test_wc_Pkcs11_FreeKeepsTokenKey(void)
{
    EXPECT_DECLS;
#ifdef TEST_PKCS11_ECC
    static CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    static CK_BBOOL        isToken = CK_TRUE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &privClass, sizeof(privClass) },
        { CKA_TOKEN, &isToken,   sizeof(isToken)   }
    };
    Pkcs11Token token;
    CK_FUNCTION_LIST func;
    CK_OBJECT_HANDLE sessObj = 0;
    CK_OBJECT_HANDLE tokObj = 0;
    ecc_key key;

    test_pkcs11_store_setup(&token, &func);
    XMEMSET(&key, 0, sizeof(key));
    ExpectIntEQ(test_pkcs11_store_create(0, tmpl, 1, &sessObj), CKR_OK);
    ExpectIntEQ(test_pkcs11_store_create(0, tmpl, 2, &tokObj), CKR_OK);

    key.devCtx = (void*)(wc_ptr_t)tokObj;
    ExpectIntEQ(test_pkcs11_free_ecc(&token, &key), 0);
    ExpectNull(key.devCtx);
    ExpectNotNull(test_pkcs11_obj(tokObj));

    key.devCtx = (void*)(wc_ptr_t)(TEST_PKCS11_MAX_OBJS + 1);
    ExpectIntEQ(test_pkcs11_free_ecc(&token, &key), 0);
    ExpectNull(key.devCtx);

    key.devCtx = (void*)(wc_ptr_t)sessObj;
    ExpectIntEQ(test_pkcs11_free_ecc(&token, &key), 0);
    ExpectNull(key.devCtx);
    ExpectNull(test_pkcs11_obj(sessObj));
    ExpectIntEQ(test_pkcs11_destroy_calls, 1);
    ExpectIntEQ(test_pkcs11_count(CK_TRUE), 1);
#endif
    return EXPECT_RESULT();
}

#ifdef TEST_PKCS11_EC_KEYGEN
static int test_pkcs11_make_ecc(ecc_key* key, WC_RNG* rng, const byte* id,
    int idLen)
{
    int ret = wc_ecc_init_id(key, (unsigned char*)id, idLen, NULL,
        INVALID_DEVID);
    if (ret == 0)
        ret = wc_ecc_make_key(rng, 32, key);
#ifdef WOLFSSL_ASYNC_CRYPT
    if (ret == WC_NO_ERR_TRACE(WC_PENDING_E))
        ret = wc_AsyncWait(ret, &key->asyncDev, WC_ASYNC_FLAG_NONE);
#endif
    return ret;
}
#endif

#if defined(TEST_PKCS11_EC_KEYGEN) && defined(HAVE_ECC_KEY_IMPORT)
static CK_OBJECT_HANDLE test_pkcs11_find_obj(CK_OBJECT_CLASS cls,
    CK_BBOOL onToken)
{
    int i;

    for (i = 0; i < TEST_PKCS11_MAX_OBJS; i++) {
        if (test_pkcs11_objs[i].used && test_pkcs11_objs[i].cls == cls &&
                test_pkcs11_objs[i].onToken == onToken)
            return (CK_OBJECT_HANDLE)(i + 1);
    }
    return 0;
}
#endif

#if !defined(NO_RSA) && !defined(NO_PKCS11_RSA) && \
    defined(HAVE_WOLF_BIGINT) && \
    defined(USE_WOLFSSL_MEMORY) && !defined(WOLFSSL_STATIC_MEMORY) && \
    !defined(WOLFSSL_DEBUG_MEMORY)
static wolfSSL_Malloc_cb  test_pkcs11_mf = NULL;
static wolfSSL_Free_cb    test_pkcs11_ff = NULL;
static wolfSSL_Realloc_cb test_pkcs11_rf = NULL;
static int                test_pkcs11_live = 0;

static void* test_pkcs11_malloc(size_t n)
{
    void* p = (test_pkcs11_mf != NULL) ? test_pkcs11_mf(n) : malloc(n);

    if (p != NULL)
        test_pkcs11_live++;
    return p;
}

static void test_pkcs11_free(void* p)
{
    if (p != NULL)
        test_pkcs11_live--;
    if (test_pkcs11_ff != NULL)
        test_pkcs11_ff(p);
    else
        free(p);
}

static void* test_pkcs11_realloc(void* p, size_t n)
{
    void* r = (test_pkcs11_rf != NULL) ? test_pkcs11_rf(p, n) : realloc(p, n);

    if (p == NULL && r != NULL)
        test_pkcs11_live++;
    return r;
}
#endif

#if defined(TEST_PKCS11_RSA_KEYGEN) || (!defined(NO_RSA) && \
    !defined(NO_PKCS11_RSA) && defined(HAVE_WOLF_BIGINT) && \
    defined(USE_WOLFSSL_MEMORY) && !defined(WOLFSSL_STATIC_MEMORY) && \
    !defined(WOLFSSL_DEBUG_MEMORY))
static int test_pkcs11_rsa_decrypt(Pkcs11Token* token, RsaKey* key)
{
    byte in[sizeof(test_pkcs11_modulus)];
    byte out[sizeof(test_pkcs11_modulus)];
    word32 outLen = sizeof(out);
    wc_CryptoInfo info;

    XMEMSET(in, 0, sizeof(in));
    XMEMSET(&info, 0, sizeof(info));
    info.algo_type = WC_ALGO_TYPE_PK;
    info.pk.type = WC_PK_TYPE_RSA;
    info.pk.rsa.in = in;
    info.pk.rsa.inLen = sizeof(in);
    info.pk.rsa.out = out;
    info.pk.rsa.outLen = &outLen;
    info.pk.rsa.type = RSA_PRIVATE_DECRYPT;
    info.pk.rsa.key = key;
    return wc_Pkcs11_CryptoDevCb(1, &info, token);
}
#endif

int test_wc_Pkcs11_RsaIdNoLeak(void)
{
    EXPECT_DECLS;
#if !defined(NO_RSA) && !defined(NO_PKCS11_RSA) && \
    defined(HAVE_WOLF_BIGINT) && \
    defined(USE_WOLFSSL_MEMORY) && !defined(WOLFSSL_STATIC_MEMORY) && \
    !defined(WOLFSSL_DEBUG_MEMORY)
    static unsigned char id[] = { 0x05 };
    static CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    static CK_KEY_TYPE     rsaType = CKK_RSA;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,    &privClass, sizeof(privClass) },
        { CKA_KEY_TYPE, &rsaType,   sizeof(rsaType)   },
        { CKA_ID,       id,         sizeof(id)        }
    };
    Pkcs11Token token;
    CK_FUNCTION_LIST func;
    CK_OBJECT_HANDLE obj = 0;
    RsaKey key;
    int haveAlloc = 0;

    test_pkcs11_store_setup(&token, &func);
    ExpectIntEQ(test_pkcs11_store_create(0, tmpl, 3, &obj), CKR_OK);
    ExpectIntEQ(wolfSSL_GetAllocators(&test_pkcs11_mf, &test_pkcs11_ff,
        &test_pkcs11_rf), 0);
    if (EXPECT_SUCCESS()) {
        test_pkcs11_live = 0;
        ExpectIntEQ(wolfSSL_SetAllocators(test_pkcs11_malloc,
            test_pkcs11_free, test_pkcs11_realloc), 0);
        haveAlloc = EXPECT_SUCCESS();
    }

    ExpectIntEQ(wc_InitRsaKey_Id(&key, id, (int)sizeof(id), NULL,
        INVALID_DEVID), 0);
    /* Without e the public key is read again, over the n the key holds. */
    ExpectIntEQ(wc_RsaPublicKeyDecodeRaw(test_pkcs11_modulus,
        sizeof(test_pkcs11_modulus), test_pkcs11_exponent, 0, &key), 0);
    ExpectIntEQ(test_pkcs11_rsa_decrypt(&token, &key), 0);
    test_pkcs11_modulus_reads = 0;
    ExpectIntEQ(test_pkcs11_rsa_decrypt(&token, &key), 0);
    ExpectIntEQ(test_pkcs11_modulus_reads, 0);
    ExpectIntEQ(wc_FreeRsaKey(&key), 0);
    ExpectIntEQ(test_pkcs11_live, 0);

    if (haveAlloc) {
        (void)wolfSSL_SetAllocators(test_pkcs11_mf, test_pkcs11_ff,
            test_pkcs11_rf);
    }
#endif
    return EXPECT_RESULT();
}

#define TEST_PKCS11_DEVID 0x7031

#ifndef NO_PKCS11_ECDH
    #define TEST_PKCS11_DFLT_DERIVE CK_TRUE
    #define TEST_PKCS11_NONAME_SIGN CK_FALSE
#else
    #define TEST_PKCS11_DFLT_DERIVE CK_FALSE
    #define TEST_PKCS11_NONAME_SIGN CK_TRUE
#endif

#if defined(TEST_PKCS11_EC_KEYGEN) && defined(HAVE_ECC_KEY_IMPORT)
static int test_pkcs11_ec_usage(Pkcs11Token* token, WC_RNG* rng,
    const char* label, int flags, CK_BBOOL sign, CK_BBOOL derive,
    CK_BBOOL decrypt)
{
    EXPECT_DECLS;
    ecc_key key;
    TestPkcs11Obj* obj = NULL;
    CK_OBJECT_HANDLE h = 0;

    test_pkcs11_reset();
    XMEMSET(&key, 0, sizeof(key));
    if (label == NULL)
        ExpectIntEQ(wc_ecc_init_ex(&key, NULL, TEST_PKCS11_DEVID), 0);
    else
        ExpectIntEQ(wc_ecc_init_label(&key, label, NULL, TEST_PKCS11_DEVID), 0);
    ExpectIntEQ(wc_ecc_make_key_ex2(rng, 32, &key, ECC_SECP256R1, flags), 0);
    if (EXPECT_SUCCESS())
        h = (CK_OBJECT_HANDLE)(wc_ptr_t)key.devCtx;
    ExpectNotNull(obj = test_pkcs11_obj(h));
    if (obj != NULL) {
        ExpectIntEQ(obj->cls, CKO_PRIVATE_KEY);
        ExpectIntEQ(obj->sign, sign);
        ExpectIntEQ(obj->derive, derive);
        ExpectIntEQ(obj->decrypt, decrypt);
    }
    wc_ecc_free(&key);
    (void)token;

    return EXPECT_RESULT();
}

static int test_pkcs11_store_private_only(Pkcs11Token* token, ecc_key* src)
{
    static unsigned char id[] = { 0x13 };
    byte priv[MAX_ECC_BYTES];
    word32 privSz = sizeof(priv);
    ecc_key key;
    int ret;

    ret = wc_ecc_export_private_only(src, priv, &privSz);
    if (ret == 0)
        ret = wc_ecc_init_id(&key, id, (int)sizeof(id), NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_ecc_import_private_key_ex(priv, privSz, NULL, 0, &key,
            ECC_SECP256R1);
        if (ret == 0)
            ret = wc_Pkcs11StoreKey(token, PKCS11_KEY_TYPE_EC, 0, &key);
        wc_ecc_free(&key);
    }
    wc_ForceZero(priv, sizeof(priv));
    return ret;
}
#endif

int test_wc_Pkcs11_EcKeyUsage(void)
{
    EXPECT_DECLS;
#if defined(TEST_PKCS11_EC_KEYGEN) && defined(HAVE_ECC_KEY_IMPORT)
    static const byte id[] = { 0x11 };
    Pkcs11Token token;
    CK_FUNCTION_LIST func;
    ecc_key soft;
    ecc_key gen;
    WC_RNG rng;
    word32 len = sizeof(test_pkcs11_ec_point) - 2;
    TestPkcs11Obj* priv = NULL;
#if defined(HAVE_ECC_SIGN) || !defined(NO_PKCS11_ECDH)
    wc_CryptoInfo info;
#endif
#ifdef HAVE_ECC_SIGN
    byte hash[32];
    byte sig[ECC_MAX_SIG_SIZE];
    word32 sigLen = sizeof(sig);
#endif
#ifndef NO_PKCS11_ECDH
    byte secret[sizeof(test_pkcs11_secret)];
    word32 secretLen = sizeof(secret);
#endif

    test_pkcs11_store_setup(&token, &func);
    XMEMSET(&soft, 0, sizeof(soft));
    XMEMSET(&gen, 0, sizeof(gen));
#ifdef HAVE_ECC_SIGN
    XMEMSET(hash, 0x11, sizeof(hash));
#endif
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(test_pkcs11_make_ecc(&soft, &rng, id, (int)sizeof(id)), 0);
    test_pkcs11_ec_point[0] = ASN_OCTET_STRING;
    test_pkcs11_ec_point[1] = (byte)len;
    ExpectIntEQ(wc_ecc_export_x963(&soft, test_pkcs11_ec_point + 2, &len), 0);
    ExpectIntEQ(wc_CryptoCb_RegisterDevice(TEST_PKCS11_DEVID,
        wc_Pkcs11_CryptoDevCb, &token), 0);

    ExpectIntEQ(test_pkcs11_ec_usage(&token, &rng, NULL, WC_ECC_FLAG_NONE,
        TEST_PKCS11_NONAME_SIGN, TEST_PKCS11_DFLT_DERIVE, CK_FALSE),
        TEST_SUCCESS);
    ExpectIntEQ(test_pkcs11_ec_usage(&token, &rng, "usage", WC_ECC_FLAG_NONE,
        CK_TRUE, TEST_PKCS11_DFLT_DERIVE, CK_FALSE), TEST_SUCCESS);
    ExpectIntEQ(test_pkcs11_ec_usage(&token, &rng, NULL, WC_ECC_FLAG_DEC_SIGN,
        CK_TRUE, CK_FALSE, CK_TRUE), TEST_SUCCESS);
    ExpectIntEQ(test_pkcs11_ec_usage(&token, &rng, NULL, WC_ECC_FLAG_DERIVE,
        CK_FALSE, CK_TRUE, CK_FALSE), TEST_SUCCESS);
    ExpectIntEQ(test_pkcs11_ec_usage(&token, &rng, NULL,
        WC_ECC_FLAG_DEC_SIGN | WC_ECC_FLAG_DERIVE, CK_TRUE, CK_TRUE, CK_TRUE),
        TEST_SUCCESS);
    test_pkcs11_no_ecdh = 1;
    ExpectIntEQ(test_pkcs11_ec_usage(&token, &rng, "usage", WC_ECC_FLAG_NONE,
        CK_TRUE, CK_FALSE, CK_FALSE), TEST_SUCCESS);
#ifndef NO_PKCS11_ECDH
    ExpectIntEQ(wc_ecc_init_ex(&gen, NULL, TEST_PKCS11_DEVID), 0);
    ExpectIntEQ(wc_ecc_make_key_ex2(&rng, 32, &gen, ECC_SECP256R1,
        WC_ECC_FLAG_NONE), 0);
    ExpectNull(gen.devCtx);
    ExpectIntEQ(gen.type, ECC_PRIVATEKEY);
    wc_ecc_free(&gen);
#endif

    /* A usage needs a mechanism that can do it. */
    test_pkcs11_reset();
    soft.flags = WC_ECC_FLAG_DERIVE;
    ExpectIntEQ(wc_Pkcs11StoreKey(&token, PKCS11_KEY_TYPE_EC, 0, &soft),
        WC_NO_ERR_TRACE(NOT_COMPILED_IN));
    soft.flags = WC_ECC_FLAG_DEC_SIGN | WC_ECC_FLAG_DERIVE;
    ExpectIntEQ(wc_Pkcs11StoreKey(&token, PKCS11_KEY_TYPE_EC, 0, &soft),
        WC_NO_ERR_TRACE(NOT_COMPILED_IN));
    ExpectIntEQ(test_pkcs11_count(CK_FALSE), 0);
    ExpectIntEQ(wc_ecc_init_id(&gen, (unsigned char*)id, (int)sizeof(id), NULL,
        TEST_PKCS11_DEVID), 0);
    ExpectIntEQ(wc_ecc_make_key_ex2(&rng, 32, &gen, ECC_SECP256R1,
        WC_ECC_FLAG_DEC_SIGN | WC_ECC_FLAG_DERIVE), WC_NO_ERR_TRACE(WC_HW_E));
    ExpectNull(gen.devCtx);
    wc_ecc_free(&gen);
    test_pkcs11_no_ecdh = 0;
    test_pkcs11_ecdsa_verify_only = 1;
#ifndef NO_PKCS11_ECDH
    ExpectIntEQ(test_pkcs11_ec_usage(&token, &rng, "usage", WC_ECC_FLAG_NONE,
        CK_FALSE, CK_TRUE, CK_FALSE), TEST_SUCCESS);
#endif
    ExpectIntEQ(wc_ecc_init_ex(&gen, NULL, TEST_PKCS11_DEVID), 0);
    ExpectIntEQ(wc_ecc_make_key_ex2(&rng, 32, &gen, ECC_SECP256R1,
        WC_ECC_FLAG_DEC_SIGN), 0);
    ExpectNull(gen.devCtx);
    ExpectIntEQ(gen.type, ECC_PRIVATEKEY);
    wc_ecc_free(&gen);
    ExpectIntEQ(wc_ecc_init_id(&gen, (unsigned char*)id, (int)sizeof(id), NULL,
        TEST_PKCS11_DEVID), 0);
    ExpectIntEQ(wc_ecc_make_key_ex2(&rng, 32, &gen, ECC_SECP256R1,
        WC_ECC_FLAG_DEC_SIGN), WC_NO_ERR_TRACE(WC_HW_E));
    ExpectNull(gen.devCtx);
    wc_ecc_free(&gen);
    ExpectIntEQ(wc_ecc_init_label(&gen, "usage", NULL, TEST_PKCS11_DEVID), 0);
    ExpectIntEQ(wc_ecc_make_key_ex2(&rng, 32, &gen, ECC_SECP256R1,
        WC_ECC_FLAG_DEC_SIGN), WC_NO_ERR_TRACE(WC_HW_E));
    ExpectNull(gen.devCtx);
    wc_ecc_free(&gen);
    soft.flags = WC_ECC_FLAG_DEC_SIGN;
    ExpectIntEQ(wc_Pkcs11StoreKey(&token, PKCS11_KEY_TYPE_EC, 0, &soft),
        WC_NO_ERR_TRACE(NOT_COMPILED_IN));
    ExpectIntEQ(test_pkcs11_count(CK_FALSE), 0);
    test_pkcs11_ecdsa_verify_only = 0;
    soft.flags = 0;

    /* An import makes one private object and the public one. */
    test_pkcs11_no_ecdh = 0;
    test_pkcs11_reset();
    ExpectIntEQ(wc_Pkcs11StoreKey(&token, PKCS11_KEY_TYPE_EC, 0, &soft), 0);
    ExpectNotNull(priv = test_pkcs11_obj(test_pkcs11_find_obj(CKO_PRIVATE_KEY,
        CK_FALSE)));
    if (priv != NULL) {
        ExpectIntEQ(priv->sign, CK_TRUE);
        ExpectIntEQ(priv->derive, TEST_PKCS11_DFLT_DERIVE);
    }
    ExpectIntEQ(test_pkcs11_count(CK_FALSE), 2);

    /* A failed public object takes the private one with it. */
    test_pkcs11_reset();
    test_pkcs11_fail_pub_create = 1;
    ExpectIntEQ(wc_Pkcs11StoreKey(&token, PKCS11_KEY_TYPE_EC, 0, &soft),
        WC_NO_ERR_TRACE(WC_HW_E));
    ExpectIntEQ(test_pkcs11_count(CK_FALSE), 0);
    test_pkcs11_fail_pub_create = 0;

    test_pkcs11_reset();
    soft.flags = WC_ECC_FLAG_DERIVE;
    ExpectIntEQ(wc_Pkcs11StoreKey(&token, PKCS11_KEY_TYPE_EC, 0, &soft), 0);
    ExpectNotNull(priv = test_pkcs11_obj(test_pkcs11_find_obj(CKO_PRIVATE_KEY,
        CK_FALSE)));
    if (priv != NULL) {
        ExpectIntEQ(priv->sign, CK_FALSE);
        ExpectIntEQ(priv->derive, CK_TRUE);
    }
    ExpectIntNE(test_pkcs11_find_obj(CKO_PUBLIC_KEY, CK_FALSE), 0);
    ExpectIntEQ(test_pkcs11_count(CK_FALSE), 2);
    test_pkcs11_reset();
    test_pkcs11_fail_pub_create = 1;
    ExpectIntEQ(wc_Pkcs11StoreKey(&token, PKCS11_KEY_TYPE_EC, 0, &soft), 0);
    ExpectIntEQ(test_pkcs11_count(CK_FALSE), 1);
    test_pkcs11_fail_pub_create = 0;

#ifndef NO_PKCS11_ECDH
    /* Without ECDSA on the token, a key gets derive and no public object. */
    test_pkcs11_reset();
    test_pkcs11_no_ecdsa = 1;
    soft.flags = 0;
    ExpectIntEQ(wc_Pkcs11StoreKey(&token, PKCS11_KEY_TYPE_EC, 0, &soft), 0);
    ExpectNotNull(priv = test_pkcs11_obj(test_pkcs11_find_obj(CKO_PRIVATE_KEY,
        CK_FALSE)));
    if (priv != NULL) {
        ExpectIntEQ(priv->sign, CK_FALSE);
        ExpectIntEQ(priv->derive, CK_TRUE);
    }
    ExpectIntEQ(test_pkcs11_count(CK_FALSE), 1);
    test_pkcs11_no_ecdsa = 0;
#endif

    /* A key with only its private half gets no public object. */
    test_pkcs11_reset();
    soft.flags = 0;
    ExpectIntEQ(test_pkcs11_store_private_only(&token, &soft), 0);
    ExpectIntEQ(test_pkcs11_count(CK_FALSE), 1);

    /* A software key gets only the usage of its operation on the token. */
#ifdef HAVE_ECC_SIGN
    test_pkcs11_reset();
    XMEMSET(&info, 0, sizeof(info));
    info.algo_type = WC_ALGO_TYPE_PK;
    info.pk.type = WC_PK_TYPE_ECDSA_SIGN;
    info.pk.eccsign.in = hash;
    info.pk.eccsign.inlen = sizeof(hash);
    info.pk.eccsign.out = sig;
    info.pk.eccsign.outlen = &sigLen;
    info.pk.eccsign.rng = &rng;
    info.pk.eccsign.key = &soft;
    ExpectIntEQ(wc_Pkcs11_CryptoDevCb(1, &info, &token), 0);
    ExpectIntEQ(test_pkcs11_last_priv.sign, CK_TRUE);
    ExpectIntEQ(test_pkcs11_last_priv.derive, CK_FALSE);
    ExpectIntEQ(test_pkcs11_count(CK_FALSE), 0);
#endif
#ifndef NO_PKCS11_ECDH
    test_pkcs11_reset();
    XMEMSET(&info, 0, sizeof(info));
    info.algo_type = WC_ALGO_TYPE_PK;
    info.pk.type = WC_PK_TYPE_ECDH;
    info.pk.ecdh.private_key = &soft;
    info.pk.ecdh.public_key = &soft;
    info.pk.ecdh.out = secret;
    info.pk.ecdh.outlen = &secretLen;
    ExpectIntEQ(wc_Pkcs11_CryptoDevCb(1, &info, &token), 0);
    ExpectBufEQ(secret, test_pkcs11_secret, sizeof(test_pkcs11_secret));
    ExpectIntEQ(test_pkcs11_last_priv.sign, CK_FALSE);
    ExpectIntEQ(test_pkcs11_last_priv.derive, CK_TRUE);
    ExpectIntEQ(test_pkcs11_count(CK_FALSE), 0);
#endif

    wc_CryptoCb_UnRegisterDevice(TEST_PKCS11_DEVID);
    wc_ecc_free(&soft);
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();
}

static int   test_pkcs11_opens = 0;

static CK_RV test_pkcs11_open_session(CK_SLOT_ID slotId, CK_FLAGS flags,
    CK_VOID_PTR app, CK_NOTIFY notify, CK_SESSION_HANDLE_PTR session)
{
    (void)slotId;
    (void)flags;
    (void)app;
    (void)notify;

    test_pkcs11_opens++;
    *session = 5;
    return CKR_OK;
}

static CK_RV test_pkcs11_close_session(CK_SESSION_HANDLE session)
{
    (void)session;

    return CKR_OK;
}

int test_wc_Pkcs11_FreeNoObject(void)
{
    Pkcs11Token token;
    CK_FUNCTION_LIST func;
#ifdef TEST_PKCS11_ECC
    ecc_key key;
#endif
#ifdef TEST_PKCS11_RSA_KEYGEN
    RsaKey rsa;
#endif
    EXPECT_DECLS;

    test_pkcs11_store_setup(&token, &func);
    func.C_OpenSession = test_pkcs11_open_session;
    func.C_CloseSession = test_pkcs11_close_session;
    token.handle = 0;
    test_pkcs11_opens = 0;
    ExpectIntEQ(wc_CryptoCb_RegisterDevice(TEST_PKCS11_DEVID,
        wc_Pkcs11_CryptoDevCb, &token), 0);

    /* A key with no object on the device is freed without a session. */
#ifdef TEST_PKCS11_ECC
    ExpectIntEQ(wc_ecc_init_ex(&key, NULL, TEST_PKCS11_DEVID), 0);
    wc_ecc_free(&key);
    ExpectIntEQ(test_pkcs11_free_ecc(&token, NULL), 0);
#endif
#ifdef TEST_PKCS11_RSA_KEYGEN
    ExpectIntEQ(wc_InitRsaKey_ex(&rsa, NULL, TEST_PKCS11_DEVID), 0);
    ExpectIntEQ(wc_FreeRsaKey(&rsa), 0);
#endif
    ExpectIntEQ(test_pkcs11_opens, 0);

    wc_CryptoCb_UnRegisterDevice(TEST_PKCS11_DEVID);

    return EXPECT_RESULT();
}

int test_wc_Pkcs11_KeyGenSessionClosed(void)
{
    EXPECT_DECLS;
#ifdef TEST_PKCS11_EC_KEYGEN
    static const byte id[] = { 0x61 };
    Pkcs11Token token;
    CK_FUNCTION_LIST func;
    ecc_key soft;
    ecc_key key;
    WC_RNG rng;
    word32 len = sizeof(test_pkcs11_ec_point) - 2;
#ifdef TEST_PKCS11_RSA_KEYGEN
    RsaKey rsa;
    wc_CryptoInfo info;
#endif

    test_pkcs11_store_setup(&token, &func);
    func.C_OpenSession = test_pkcs11_open_session;
    func.C_CloseSession = test_pkcs11_close_session;
    XMEMSET(&soft, 0, sizeof(soft));
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(test_pkcs11_make_ecc(&soft, &rng, id, (int)sizeof(id)), 0);
    test_pkcs11_ec_point[0] = ASN_OCTET_STRING;
    test_pkcs11_ec_point[1] = (byte)len;
    ExpectIntEQ(wc_ecc_export_x963(&soft, test_pkcs11_ec_point + 2, &len), 0);
    ExpectIntEQ(wc_CryptoCb_RegisterDevice(TEST_PKCS11_DEVID,
        wc_Pkcs11_CryptoDevCb, &token), 0);

    /* A named session key would go with a session that closes. */
    token.handle = 0;
    ExpectIntEQ(wc_ecc_init_id(&key, (unsigned char*)id, (int)sizeof(id),
        NULL, TEST_PKCS11_DEVID), 0);
    ExpectIntEQ(wc_ecc_make_key_ex2(&rng, 32, &key, ECC_SECP256R1,
        WC_ECC_FLAG_NONE), WC_NO_ERR_TRACE(BAD_STATE_E));
    ExpectNull(key.devCtx);
    wc_ecc_free(&key);
    ExpectIntEQ(wc_ecc_init_label(&key, "closes", NULL, TEST_PKCS11_DEVID), 0);
    ExpectIntEQ(wc_ecc_make_key_ex2(&rng, 32, &key, ECC_SECP256R1,
        WC_ECC_FLAG_NONE), WC_NO_ERR_TRACE(BAD_STATE_E));
    ExpectNull(key.devCtx);
    wc_ecc_free(&key);
    test_pkcs11_opens = 0;
    ExpectIntEQ(wc_Pkcs11StoreKey(&token, PKCS11_KEY_TYPE_EC, 0, &soft),
        WC_NO_ERR_TRACE(BAD_STATE_E));
    ExpectIntEQ(test_pkcs11_opens, 0);
#ifdef TEST_PKCS11_RSA_KEYGEN
    ExpectIntEQ(wc_InitRsaKey_Id(&rsa, (unsigned char*)id, (int)sizeof(id),
        NULL, TEST_PKCS11_DEVID), 0);
    ExpectIntEQ(wc_MakeRsaKey(&rsa, 2048, WC_RSA_EXPONENT, &rng),
        WC_NO_ERR_TRACE(BAD_STATE_E));
    ExpectNull(rsa.devCtx);
    ExpectIntEQ(wc_FreeRsaKey(&rsa), 0);
#endif
    ExpectIntEQ(test_pkcs11_count(CK_FALSE), 0);

    /* A key without a name is generated in software. */
    ExpectIntEQ(wc_ecc_init_ex(&key, NULL, TEST_PKCS11_DEVID), 0);
    ExpectIntEQ(wc_ecc_make_key_ex2(&rng, 32, &key, ECC_SECP256R1,
        WC_ECC_FLAG_NONE), 0);
    ExpectNull(key.devCtx);
    ExpectIntEQ(key.type, ECC_PRIVATEKEY);
    wc_ecc_free(&key);
#ifdef TEST_PKCS11_RSA_KEYGEN
    ExpectIntEQ(wc_InitRsaKey_ex(&rsa, NULL, TEST_PKCS11_DEVID), 0);
    XMEMSET(&info, 0, sizeof(info));
    info.algo_type = WC_ALGO_TYPE_PK;
    info.pk.type = WC_PK_TYPE_RSA_KEYGEN;
    info.pk.rsakg.key = &rsa;
    info.pk.rsakg.size = 2048;
    info.pk.rsakg.e = WC_RSA_EXPONENT;
    info.pk.rsakg.rng = &rng;
    ExpectIntEQ(wc_Pkcs11_CryptoDevCb(TEST_PKCS11_DEVID, &info, &token),
        WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE));
    ExpectNull(rsa.devCtx);
    ExpectIntEQ(wc_FreeRsaKey(&rsa), 0);
#endif
    ExpectIntEQ(test_pkcs11_count(CK_FALSE), 0);

    /* A session key made in the open session is kept. */
    test_pkcs11_reset();
    token.handle = 1;
    ExpectIntEQ(wc_ecc_init_id(&key, (unsigned char*)id, (int)sizeof(id),
        NULL, TEST_PKCS11_DEVID), 0);
    ExpectIntEQ(wc_ecc_make_key_ex2(&rng, 32, &key, ECC_SECP256R1,
        WC_ECC_FLAG_NONE), 0);
    ExpectNotNull(key.devCtx);
    wc_ecc_free(&key);

    wc_CryptoCb_UnRegisterDevice(TEST_PKCS11_DEVID);
    wc_ecc_free(&soft);
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();
}

int test_wc_Pkcs11_RsaKeyGenExponent(void)
{
    EXPECT_DECLS;
#ifdef TEST_PKCS11_RSA_KEYGEN
    static const byte exp65539[] = { 0x01, 0x00, 0x03 };
    Pkcs11Token token;
    CK_FUNCTION_LIST func;
    RsaKey key;
    WC_RNG rng;

    test_pkcs11_store_setup(&token, &func);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_CryptoCb_RegisterDevice(TEST_PKCS11_DEVID,
        wc_Pkcs11_CryptoDevCb, &token), 0);

    ExpectIntEQ(wc_InitRsaKey_ex(&key, NULL, TEST_PKCS11_DEVID), 0);
    ExpectIntEQ(wc_MakeRsaKey(&key, 2048, 65539, &rng), 0);
    ExpectIntEQ(test_pkcs11_keygen_exp_len, sizeof(exp65539));
    ExpectBufEQ(test_pkcs11_keygen_exp, exp65539, sizeof(exp65539));
    ExpectIntEQ(wc_FreeRsaKey(&key), 0);

    /* The next key gets the default exponent again. */
    ExpectIntEQ(wc_InitRsaKey_ex(&key, NULL, TEST_PKCS11_DEVID), 0);
    ExpectIntEQ(wc_MakeRsaKey(&key, 2048, WC_RSA_EXPONENT, &rng), 0);
    ExpectIntEQ(test_pkcs11_keygen_exp_len, sizeof(test_pkcs11_exponent));
    ExpectBufEQ(test_pkcs11_keygen_exp, test_pkcs11_exponent,
        sizeof(test_pkcs11_exponent));
    ExpectIntEQ(wc_FreeRsaKey(&key), 0);

    wc_CryptoCb_UnRegisterDevice(TEST_PKCS11_DEVID);
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();
}

int test_wc_Pkcs11_RsaKeyGenError(void)
{
    EXPECT_DECLS;
#ifdef TEST_PKCS11_RSA_KEYGEN
    Pkcs11Token token;
    CK_FUNCTION_LIST func;
    RsaKey key;
#ifdef TEST_PKCS11_EC_KEYGEN
    ecc_key ecc;
#endif
    WC_RNG rng;
#if defined(HAVE_WOLF_BIGINT) && defined(USE_WOLFSSL_MEMORY) && \
    !defined(WOLFSSL_STATIC_MEMORY) && !defined(WOLFSSL_DEBUG_MEMORY)
    int haveAlloc = 0;
#endif

    test_pkcs11_store_setup(&token, &func);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_CryptoCb_RegisterDevice(TEST_PKCS11_DEVID,
        wc_Pkcs11_CryptoDevCb, &token), 0);

#if defined(HAVE_WOLF_BIGINT) && defined(USE_WOLFSSL_MEMORY) && \
    !defined(WOLFSSL_STATIC_MEMORY) && !defined(WOLFSSL_DEBUG_MEMORY)
    /* Freeing the key on the device must still free its software parts. */
    ExpectIntEQ(wolfSSL_GetAllocators(&test_pkcs11_mf, &test_pkcs11_ff,
        &test_pkcs11_rf), 0);
    if (EXPECT_SUCCESS()) {
        test_pkcs11_live = 0;
        ExpectIntEQ(wolfSSL_SetAllocators(test_pkcs11_malloc,
            test_pkcs11_free, test_pkcs11_realloc), 0);
        haveAlloc = EXPECT_SUCCESS();
    }
#endif
    ExpectIntEQ(wc_InitRsaKey_ex(&key, NULL, TEST_PKCS11_DEVID), 0);
    ExpectIntEQ(wc_MakeRsaKey(&key, 2048, WC_RSA_EXPONENT, &rng), 0);
    ExpectIntEQ(test_pkcs11_count(CK_FALSE), 1);
    ExpectNotNull(key.devCtx);
    test_pkcs11_find_calls = 0;
    test_pkcs11_modulus_reads = 0;
    ExpectIntEQ(test_pkcs11_rsa_decrypt(&token, &key), 0);
    ExpectIntEQ(test_pkcs11_find_calls, 0);
    ExpectIntEQ(test_pkcs11_modulus_reads, 0);
    ExpectIntEQ(wc_FreeRsaKey(&key), 0);
    ExpectIntEQ(test_pkcs11_count(CK_FALSE), 0);
#if defined(HAVE_WOLF_BIGINT) && defined(USE_WOLFSSL_MEMORY) && \
    !defined(WOLFSSL_STATIC_MEMORY) && !defined(WOLFSSL_DEBUG_MEMORY)
    if (haveAlloc) {
        (void)wolfSSL_SetAllocators(test_pkcs11_mf, test_pkcs11_ff,
            test_pkcs11_rf);
        ExpectIntEQ(test_pkcs11_live, 0);
    }
#endif

    /* A failed read of the public key fails keygen and leaves no object. */
    test_pkcs11_reset();
    test_pkcs11_fail_modulus = 1;
    ExpectIntEQ(wc_InitRsaKey_ex(&key, NULL, TEST_PKCS11_DEVID), 0);
    ExpectIntEQ(wc_MakeRsaKey(&key, 2048, WC_RSA_EXPONENT, &rng),
        WC_NO_ERR_TRACE(WC_HW_E));
    ExpectIntEQ(test_pkcs11_count(CK_FALSE), 0);
    ExpectIntEQ(wc_FreeRsaKey(&key), 0);

    test_pkcs11_reset();
    test_pkcs11_fail_keygen = 1;
    ExpectIntEQ(wc_InitRsaKey_ex(&key, NULL, TEST_PKCS11_DEVID), 0);
    ExpectIntEQ(wc_MakeRsaKey(&key, 2048, WC_RSA_EXPONENT, &rng),
        WC_NO_ERR_TRACE(WC_HW_E));
    ExpectIntEQ(wc_FreeRsaKey(&key), 0);
#ifdef TEST_PKCS11_EC_KEYGEN
    ExpectIntEQ(wc_ecc_init_ex(&ecc, NULL, TEST_PKCS11_DEVID), 0);
    ExpectIntEQ(wc_ecc_make_key_ex2(&rng, 32, &ecc, ECC_SECP256R1,
        WC_ECC_FLAG_NONE), WC_NO_ERR_TRACE(WC_HW_E));
    wc_ecc_free(&ecc);
#endif
    test_pkcs11_fail_keygen = 0;

    wc_CryptoCb_UnRegisterDevice(TEST_PKCS11_DEVID);
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();
}

#endif /* TEST_PKCS11_ECDSA */
