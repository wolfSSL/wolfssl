/* test_she.c
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

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include <wolfssl/wolfcrypt/wc_she.h>
#include <wolfssl/wolfcrypt/types.h>
#ifdef WOLF_CRYPTO_CB
    #include <wolfssl/wolfcrypt/cryptocb.h>
#endif
#include <tests/api/api.h>
#include <tests/api/test_she.h>

/* Common test vector data */
#if defined(WOLFSSL_SHE) && !defined(NO_AES)
static const byte sheTestUid[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};
static const byte sheTestAuthKey[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
static const byte sheTestNewKey[] = {
    0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
    0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00
};
static const byte sheTestExpM1[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x41
};
static const byte sheTestExpM4[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x41,
    0xb4, 0x72, 0xe8, 0xd8, 0x72, 0x7d, 0x70, 0xd5,
    0x72, 0x95, 0xe7, 0x48, 0x49, 0xa2, 0x79, 0x17
};
static const byte sheTestExpM5[] = {
    0x82, 0x0d, 0x8d, 0x95, 0xdc, 0x11, 0xb4, 0x66,
    0x88, 0x78, 0x16, 0x0c, 0xb2, 0xa4, 0xe2, 0x3e
};
#endif

int test_wc_SHE_Init(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHE) && !defined(NO_AES)
    wc_SHE she;

    ExpectIntEQ(wc_SHE_Init(&she, NULL, INVALID_DEVID), 0);
    ExpectTrue(she.heap == NULL);
    ExpectIntEQ(she.devId, INVALID_DEVID);
    wc_SHE_Free(&she);

    ExpectIntEQ(wc_SHE_Init(NULL, NULL, INVALID_DEVID),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    return EXPECT_RESULT();
}

int test_wc_SHE_Init_Id(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHE) && !defined(NO_AES) && defined(WOLF_PRIVATE_KEY_ID)
    wc_SHE she;
    unsigned char testId[] = {0x01, 0x02, 0x03, 0x04};

    ExpectIntEQ(wc_SHE_Init_Id(&she, testId, (int)sizeof(testId),
                                NULL, INVALID_DEVID), 0);
    ExpectIntEQ(she.idLen, (int)sizeof(testId));
    wc_SHE_Free(&she);

    ExpectIntEQ(wc_SHE_Init_Id(NULL, testId, (int)sizeof(testId),
                                NULL, INVALID_DEVID),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SHE_Init_Id(&she, testId, WC_SHE_MAX_ID_LEN + 1,
                                NULL, INVALID_DEVID),
                WC_NO_ERR_TRACE(BUFFER_E));
    ExpectIntEQ(wc_SHE_Init_Id(&she, testId, -1, NULL, INVALID_DEVID),
                WC_NO_ERR_TRACE(BUFFER_E));
#endif
    return EXPECT_RESULT();
}

int test_wc_SHE_Init_Label(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHE) && !defined(NO_AES) && defined(WOLF_PRIVATE_KEY_ID)
    wc_SHE she;

    ExpectIntEQ(wc_SHE_Init_Label(&she, "test", NULL, INVALID_DEVID), 0);
    ExpectIntEQ(she.labelLen, 4);
    wc_SHE_Free(&she);

    ExpectIntEQ(wc_SHE_Init_Label(NULL, "test", NULL, INVALID_DEVID),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SHE_Init_Label(&she, NULL, NULL, INVALID_DEVID),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SHE_Init_Label(&she, "", NULL, INVALID_DEVID),
                WC_NO_ERR_TRACE(BUFFER_E));
#endif
    return EXPECT_RESULT();
}

int test_wc_SHE_Free(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHE) && !defined(NO_AES)
    wc_SHE she;

    ExpectIntEQ(wc_SHE_Init(&she, NULL, INVALID_DEVID), 0);
    wc_SHE_Free(&she);
    ExpectIntEQ(she.devId, 0);

    wc_SHE_Free(NULL);
#endif
    return EXPECT_RESULT();
}

int test_wc_SHE_ImportM1M2M3(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHE) && !defined(NO_AES) && \
    (defined(WOLF_CRYPTO_CB) && !defined(NO_WC_SHE_IMPORT_M123))
    wc_SHE she;
    byte m1[WC_SHE_M1_SZ] = {0};
    byte m2[WC_SHE_M2_SZ] = {0};
    byte m3[WC_SHE_M3_SZ] = {0};

    ExpectIntEQ(wc_SHE_Init(&she, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_SHE_ImportM1M2M3(&she,
                    m1, WC_SHE_M1_SZ, m2, WC_SHE_M2_SZ, m3, WC_SHE_M3_SZ), 0);
    ExpectIntEQ(she.generated, 1);

    ExpectIntEQ(wc_SHE_ImportM1M2M3(NULL,
                    m1, WC_SHE_M1_SZ, m2, WC_SHE_M2_SZ, m3, WC_SHE_M3_SZ),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SHE_ImportM1M2M3(&she,
                    m1, WC_SHE_M1_SZ - 1, m2, WC_SHE_M2_SZ, m3, WC_SHE_M3_SZ),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_SHE_Free(&she);
#endif
    return EXPECT_RESULT();
}

int test_wc_SHE_AesMp16(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHE) && !defined(NO_AES)
    Aes aes;
    byte out[WC_SHE_KEY_SZ];
    byte input[WC_SHE_KEY_SZ * 2] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x01, 0x01, 0x53, 0x48, 0x45, 0x00, 0x80, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xB0
    };
    byte shortInput[17] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0xAA
    };

    ExpectIntEQ(wc_AesInit(&aes, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_SHE_AesMp16(&aes, input, sizeof(input), out), 0);

    ExpectIntEQ(wc_AesInit(&aes, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_SHE_AesMp16(&aes, shortInput, sizeof(shortInput), out), 0);

    ExpectIntEQ(wc_SHE_AesMp16(NULL, input, sizeof(input), out),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SHE_AesMp16(&aes, NULL, sizeof(input), out),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SHE_AesMp16(&aes, input, 0, out),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SHE_AesMp16(&aes, input, sizeof(input), NULL),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_AesFree(&aes);
#endif
    return EXPECT_RESULT();
}

int test_wc_SHE_GenerateM1M2M3(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHE) && !defined(NO_AES)
    wc_SHE she;
    byte m1[WC_SHE_M1_SZ];
    byte m2[WC_SHE_M2_SZ];
    byte m3[WC_SHE_M3_SZ];

    ExpectIntEQ(wc_SHE_Init(&she, NULL, INVALID_DEVID), 0);

    /* Generate and verify M1 against test vector */
    ExpectIntEQ(wc_SHE_GenerateM1M2M3(&she,
                    sheTestUid, sizeof(sheTestUid),
                    WC_SHE_MASTER_ECU_KEY_ID, sheTestAuthKey, sizeof(sheTestAuthKey),
                    4, sheTestNewKey, sizeof(sheTestNewKey),
                    1, 0,
                    m1, WC_SHE_M1_SZ, m2, WC_SHE_M2_SZ, m3, WC_SHE_M3_SZ), 0);
    ExpectIntEQ(XMEMCMP(m1, sheTestExpM1, WC_SHE_M1_SZ), 0);

    /* Bad args */
    ExpectIntEQ(wc_SHE_GenerateM1M2M3(NULL,
                    sheTestUid, sizeof(sheTestUid),
                    1, sheTestAuthKey, sizeof(sheTestAuthKey),
                    4, sheTestNewKey, sizeof(sheTestNewKey),
                    1, 0,
                    m1, WC_SHE_M1_SZ, m2, WC_SHE_M2_SZ, m3, WC_SHE_M3_SZ),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_SHE_Free(&she);
#endif
    return EXPECT_RESULT();
}

int test_wc_SHE_GenerateM4M5(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHE) && !defined(NO_AES)
    wc_SHE she;
    byte m4[WC_SHE_M4_SZ];
    byte m5[WC_SHE_M5_SZ];

    ExpectIntEQ(wc_SHE_Init(&she, NULL, INVALID_DEVID), 0);

    /* Generate and verify against test vector */
    ExpectIntEQ(wc_SHE_GenerateM4M5(&she,
                    sheTestUid, sizeof(sheTestUid),
                    WC_SHE_MASTER_ECU_KEY_ID, 4,
                    sheTestNewKey, sizeof(sheTestNewKey), 1,
                    m4, WC_SHE_M4_SZ, m5, WC_SHE_M5_SZ), 0);
    ExpectIntEQ(XMEMCMP(m4, sheTestExpM4, WC_SHE_M4_SZ), 0);
    ExpectIntEQ(XMEMCMP(m5, sheTestExpM5, WC_SHE_M5_SZ), 0);

    /* Bad args */
    ExpectIntEQ(wc_SHE_GenerateM4M5(NULL,
                    sheTestUid, sizeof(sheTestUid),
                    1, 4, sheTestNewKey, sizeof(sheTestNewKey), 1,
                    m4, WC_SHE_M4_SZ, m5, WC_SHE_M5_SZ),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_SHE_Free(&she);
#endif
    return EXPECT_RESULT();
}

#if defined(WOLFSSL_SHE_EXTENDED) && defined(WOLFSSL_SHE) && !defined(NO_AES)

int test_wc_SHE_SetKdfConstants(void)
{
    EXPECT_DECLS;
    wc_SHE she;
    byte m1Def[WC_SHE_M1_SZ];
    byte m2Def[WC_SHE_M2_SZ];
    byte m3Def[WC_SHE_M3_SZ];
    byte m1Cust[WC_SHE_M1_SZ];
    byte m2Cust[WC_SHE_M2_SZ];
    byte m3Cust[WC_SHE_M3_SZ];
    byte m4[WC_SHE_M4_SZ];
    byte m5[WC_SHE_M5_SZ];
    byte customEncC[WC_SHE_KEY_SZ] = {0};
    byte customMacC[WC_SHE_KEY_SZ] = {0};

    customEncC[0] = 0xFF;
    customMacC[0] = 0xFE;

    /* Generate with defaults */
    ExpectIntEQ(wc_SHE_Init(&she, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_SHE_GenerateM1M2M3(&she,
                    sheTestUid, sizeof(sheTestUid),
                    WC_SHE_MASTER_ECU_KEY_ID, sheTestAuthKey, sizeof(sheTestAuthKey),
                    4, sheTestNewKey, sizeof(sheTestNewKey), 1, 0,
                    m1Def, WC_SHE_M1_SZ, m2Def, WC_SHE_M2_SZ,
                    m3Def, WC_SHE_M3_SZ), 0);
    wc_SHE_Free(&she);

    /* Generate with custom KDF constants */
    ExpectIntEQ(wc_SHE_Init(&she, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_SHE_SetKdfConstants(&she,
                    customEncC, WC_SHE_KEY_SZ,
                    customMacC, WC_SHE_KEY_SZ), 0);
    ExpectIntEQ(she.kdfEncOverride, 1);
    ExpectIntEQ(she.kdfMacOverride, 1);

    ExpectIntEQ(wc_SHE_GenerateM1M2M3(&she,
                    sheTestUid, sizeof(sheTestUid),
                    WC_SHE_MASTER_ECU_KEY_ID, sheTestAuthKey, sizeof(sheTestAuthKey),
                    4, sheTestNewKey, sizeof(sheTestNewKey), 1, 0,
                    m1Cust, WC_SHE_M1_SZ, m2Cust, WC_SHE_M2_SZ,
                    m3Cust, WC_SHE_M3_SZ), 0);

    /* M1 same, M2 should differ */
    ExpectIntEQ(XMEMCMP(m1Def, m1Cust, WC_SHE_M1_SZ), 0);
    ExpectIntNE(XMEMCMP(m2Def, m2Cust, WC_SHE_M2_SZ), 0);

    /* Bad args */
    ExpectIntEQ(wc_SHE_SetKdfConstants(NULL,
                    customEncC, WC_SHE_KEY_SZ, NULL, 0),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SHE_SetKdfConstants(&she,
                    customEncC, WC_SHE_KEY_SZ - 1, NULL, 0),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SHE_SetKdfConstants(&she,
                    NULL, 0, customMacC, WC_SHE_KEY_SZ - 1),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test KDF override in M4M5 path */
    ExpectIntEQ(wc_SHE_GenerateM4M5(&she,
                    sheTestUid, sizeof(sheTestUid),
                    WC_SHE_MASTER_ECU_KEY_ID, 4,
                    sheTestNewKey, sizeof(sheTestNewKey), 1,
                    m4, WC_SHE_M4_SZ, m5, WC_SHE_M5_SZ), 0);

    wc_SHE_Free(&she);
    return EXPECT_RESULT();
}

int test_wc_SHE_SetM2M4Header(void)
{
    EXPECT_DECLS;
    wc_SHE she;
    byte customHeader[WC_SHE_KEY_SZ] = {0};
    byte m1Def[WC_SHE_M1_SZ];
    byte m2Def[WC_SHE_M2_SZ];
    byte m3Def[WC_SHE_M3_SZ];
    byte m1Ovr[WC_SHE_M1_SZ];
    byte m2Ovr[WC_SHE_M2_SZ];
    byte m3Ovr[WC_SHE_M3_SZ];
    byte m4Def[WC_SHE_M4_SZ];
    byte m5Def[WC_SHE_M5_SZ];
    byte m4Ovr[WC_SHE_M4_SZ];
    byte m5Ovr[WC_SHE_M5_SZ];

    /* Bad args */
    ExpectIntEQ(wc_SHE_SetM2Header(NULL, customHeader, WC_SHE_KEY_SZ),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SHE_SetM4Header(NULL, customHeader, WC_SHE_KEY_SZ),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_SHE_Init(&she, NULL, INVALID_DEVID), 0);

    ExpectIntEQ(wc_SHE_SetM2Header(&she, NULL, WC_SHE_KEY_SZ),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SHE_SetM2Header(&she, customHeader, WC_SHE_KEY_SZ - 1),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Generate M1M2M3 with defaults */
    ExpectIntEQ(wc_SHE_GenerateM1M2M3(&she,
                    sheTestUid, sizeof(sheTestUid),
                    WC_SHE_MASTER_ECU_KEY_ID, sheTestAuthKey, sizeof(sheTestAuthKey),
                    4, sheTestNewKey, sizeof(sheTestNewKey), 1, 0,
                    m1Def, WC_SHE_M1_SZ, m2Def, WC_SHE_M2_SZ,
                    m3Def, WC_SHE_M3_SZ), 0);
    wc_SHE_Free(&she);

    /* Generate with overridden M2 header */
    ExpectIntEQ(wc_SHE_Init(&she, NULL, INVALID_DEVID), 0);
    customHeader[0] = 0xFF;
    ExpectIntEQ(wc_SHE_SetM2Header(&she, customHeader, WC_SHE_KEY_SZ), 0);
    ExpectIntEQ(she.m2pOverride, 1);

    ExpectIntEQ(wc_SHE_GenerateM1M2M3(&she,
                    sheTestUid, sizeof(sheTestUid),
                    WC_SHE_MASTER_ECU_KEY_ID, sheTestAuthKey, sizeof(sheTestAuthKey),
                    4, sheTestNewKey, sizeof(sheTestNewKey), 1, 0,
                    m1Ovr, WC_SHE_M1_SZ, m2Ovr, WC_SHE_M2_SZ,
                    m3Ovr, WC_SHE_M3_SZ), 0);

    ExpectIntEQ(XMEMCMP(m1Def, m1Ovr, WC_SHE_M1_SZ), 0);
    ExpectIntNE(XMEMCMP(m2Def, m2Ovr, WC_SHE_M2_SZ), 0);
    wc_SHE_Free(&she);

    /* Test M4 header override */
    ExpectIntEQ(wc_SHE_Init(&she, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_SHE_GenerateM4M5(&she,
                    sheTestUid, sizeof(sheTestUid),
                    WC_SHE_MASTER_ECU_KEY_ID, 4,
                    sheTestNewKey, sizeof(sheTestNewKey), 1,
                    m4Def, WC_SHE_M4_SZ, m5Def, WC_SHE_M5_SZ), 0);
    wc_SHE_Free(&she);

    ExpectIntEQ(wc_SHE_Init(&she, NULL, INVALID_DEVID), 0);
    XMEMSET(customHeader, 0xBB, WC_SHE_KEY_SZ);
    ExpectIntEQ(wc_SHE_SetM4Header(&she, customHeader, WC_SHE_KEY_SZ), 0);
    ExpectIntEQ(she.m4pOverride, 1);

    ExpectIntEQ(wc_SHE_GenerateM4M5(&she,
                    sheTestUid, sizeof(sheTestUid),
                    WC_SHE_MASTER_ECU_KEY_ID, 4,
                    sheTestNewKey, sizeof(sheTestNewKey), 1,
                    m4Ovr, WC_SHE_M4_SZ, m5Ovr, WC_SHE_M5_SZ), 0);

    ExpectIntNE(XMEMCMP(m4Def, m4Ovr, WC_SHE_M4_SZ), 0);
    wc_SHE_Free(&she);

    return EXPECT_RESULT();
}

#endif /* WOLFSSL_SHE_EXTENDED && WOLFSSL_SHE && !NO_AES */

#if defined(WOLF_CRYPTO_CB) && defined(WOLFSSL_SHE) && !defined(NO_AES)

/* SHE callback -- re-calls with software devId */
static int test_she_crypto_cb(int devIdArg, wc_CryptoInfo* info, void* ctx)
{
    wc_SHE* she;
    int savedDevId;
    int ret;

    (void)ctx;
    (void)devIdArg;

    if (info == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLF_CRYPTO_CB_FREE
    if (info->algo_type == WC_ALGO_TYPE_FREE) {
        if (info->free.algo == WC_ALGO_TYPE_SHE) {
            she = (wc_SHE*)info->free.obj;
            she->devId = INVALID_DEVID;
            wc_SHE_Free(she);
            return 0;
        }
        return CRYPTOCB_UNAVAILABLE;
    }
#endif

    if (info->algo_type != WC_ALGO_TYPE_SHE) {
        return CRYPTOCB_UNAVAILABLE;
    }

    she = (wc_SHE*)info->she.she;
    if (she == NULL) {
        return BAD_FUNC_ARG;
    }

    savedDevId = she->devId;
    she->devId = INVALID_DEVID;

    switch (info->she.type) {
        case WC_SHE_GET_UID:
            ret = 0;
            break;
        case WC_SHE_GET_COUNTER:
        {
            static word32 simCounter = 0;
            if (info->she.op.getCounter.counter != NULL) {
                *info->she.op.getCounter.counter = ++simCounter;
            }
            ret = 0;
            break;
        }
        case WC_SHE_GENERATE_M1M2M3:
            ret = wc_SHE_GenerateM1M2M3(she,
                      info->she.op.generateM1M2M3.uid,
                      info->she.op.generateM1M2M3.uidSz,
                      info->she.op.generateM1M2M3.authKeyId,
                      info->she.op.generateM1M2M3.authKey,
                      info->she.op.generateM1M2M3.authKeySz,
                      info->she.op.generateM1M2M3.targetKeyId,
                      info->she.op.generateM1M2M3.newKey,
                      info->she.op.generateM1M2M3.newKeySz,
                      info->she.op.generateM1M2M3.counter,
                      info->she.op.generateM1M2M3.flags,
                      info->she.op.generateM1M2M3.m1,
                      info->she.op.generateM1M2M3.m1Sz,
                      info->she.op.generateM1M2M3.m2,
                      info->she.op.generateM1M2M3.m2Sz,
                      info->she.op.generateM1M2M3.m3,
                      info->she.op.generateM1M2M3.m3Sz);
            break;
        case WC_SHE_GENERATE_M4M5:
            if (info->she.op.generateM4M5.uid == NULL &&
                she->generated) {
                /* LoadKey flow: M1/M2/M3 already imported, simulate HSM
                 * returning M4/M5 from known test vectors. */
                if (info->she.op.generateM4M5.m4 != NULL)
                    XMEMCPY(info->she.op.generateM4M5.m4,
                            sheTestExpM4, WC_SHE_M4_SZ);
                if (info->she.op.generateM4M5.m5 != NULL)
                    XMEMCPY(info->she.op.generateM4M5.m5,
                            sheTestExpM5, WC_SHE_M5_SZ);
                ret = 0;
            }
            else {
                ret = wc_SHE_GenerateM4M5(she,
                          info->she.op.generateM4M5.uid,
                          info->she.op.generateM4M5.uidSz,
                          info->she.op.generateM4M5.authKeyId,
                          info->she.op.generateM4M5.targetKeyId,
                          info->she.op.generateM4M5.newKey,
                          info->she.op.generateM4M5.newKeySz,
                          info->she.op.generateM4M5.counter,
                          info->she.op.generateM4M5.m4,
                          info->she.op.generateM4M5.m4Sz,
                          info->she.op.generateM4M5.m5,
                          info->she.op.generateM4M5.m5Sz);
            }
            break;
        case WC_SHE_EXPORT_KEY:
            /* Simulate hardware export -- fill with test pattern */
            if (info->she.op.exportKey.m1 != NULL) {
                XMEMSET(info->she.op.exportKey.m1, 0x11, WC_SHE_M1_SZ);
            }
            if (info->she.op.exportKey.m2 != NULL) {
                XMEMSET(info->she.op.exportKey.m2, 0x22, WC_SHE_M2_SZ);
            }
            if (info->she.op.exportKey.m3 != NULL) {
                XMEMSET(info->she.op.exportKey.m3, 0x33, WC_SHE_M3_SZ);
            }
            if (info->she.op.exportKey.m4 != NULL) {
                XMEMSET(info->she.op.exportKey.m4, 0x44, WC_SHE_M4_SZ);
            }
            if (info->she.op.exportKey.m5 != NULL) {
                XMEMSET(info->she.op.exportKey.m5, 0x55, WC_SHE_M5_SZ);
            }
            ret = 0;
            break;
        default:
            ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
            break;
    }

    she->devId = savedDevId;
    return ret;
}

int test_wc_SHE_CryptoCb(void)
{
    EXPECT_DECLS;
    wc_SHE she;
    int sheTestDevId = 54321;
    byte m1[WC_SHE_M1_SZ];
    byte m2[WC_SHE_M2_SZ];
    byte m3[WC_SHE_M3_SZ];
    byte m4[WC_SHE_M4_SZ];
    byte m5[WC_SHE_M5_SZ];

    ExpectIntEQ(wc_CryptoCb_RegisterDevice(sheTestDevId,
                                            test_she_crypto_cb, NULL), 0);
    ExpectIntEQ(wc_SHE_Init(&she, NULL, sheTestDevId), 0);

    /* Generate M1/M2/M3 via callback */
    ExpectIntEQ(wc_SHE_GenerateM1M2M3(&she,
                    sheTestUid, sizeof(sheTestUid),
                    WC_SHE_MASTER_ECU_KEY_ID, sheTestAuthKey, sizeof(sheTestAuthKey),
                    4, sheTestNewKey, sizeof(sheTestNewKey), 1, 0,
                    m1, WC_SHE_M1_SZ, m2, WC_SHE_M2_SZ, m3, WC_SHE_M3_SZ), 0);
    ExpectIntEQ(XMEMCMP(m1, sheTestExpM1, WC_SHE_M1_SZ), 0);

    /* Generate M4/M5 via callback */
    ExpectIntEQ(wc_SHE_GenerateM4M5(&she,
                    sheTestUid, sizeof(sheTestUid),
                    WC_SHE_MASTER_ECU_KEY_ID, 4,
                    sheTestNewKey, sizeof(sheTestNewKey), 1,
                    m4, WC_SHE_M4_SZ, m5, WC_SHE_M5_SZ), 0);
    ExpectIntEQ(XMEMCMP(m4, sheTestExpM4, WC_SHE_M4_SZ), 0);
    ExpectIntEQ(XMEMCMP(m5, sheTestExpM5, WC_SHE_M5_SZ), 0);

    /* ExportKey via callback -- simulated hardware */
#if !defined(NO_WC_SHE_EXPORTKEY)
    {
        byte em1[WC_SHE_M1_SZ];
        byte em2[WC_SHE_M2_SZ];
        byte em3[WC_SHE_M3_SZ];
        byte em4[WC_SHE_M4_SZ];
        byte em5[WC_SHE_M5_SZ];
        byte pat[WC_SHE_M1_SZ];

        ExpectIntEQ(wc_SHE_ExportKey(&she,
                        em1, WC_SHE_M1_SZ, em2, WC_SHE_M2_SZ,
                        em3, WC_SHE_M3_SZ, em4, WC_SHE_M4_SZ,
                        em5, WC_SHE_M5_SZ, NULL), 0);

        /* Verify callback filled with test pattern */
        XMEMSET(pat, 0x11, WC_SHE_M1_SZ);
        ExpectIntEQ(XMEMCMP(em1, pat, WC_SHE_M1_SZ), 0);

        /* Bad args */
        ExpectIntEQ(wc_SHE_ExportKey(NULL,
                        em1, WC_SHE_M1_SZ, em2, WC_SHE_M2_SZ,
                        em3, WC_SHE_M3_SZ, em4, WC_SHE_M4_SZ,
                        em5, WC_SHE_M5_SZ, NULL),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    }
#endif

#if !defined(NO_WC_SHE_GETUID)
    {
        byte cbUid[WC_SHE_UID_SZ];
        ExpectIntEQ(wc_SHE_GetUID(&she, cbUid, WC_SHE_UID_SZ, NULL), 0);
        ExpectIntEQ(wc_SHE_GetUID(NULL, cbUid, WC_SHE_UID_SZ, NULL),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_SHE_GetUID(&she, NULL, WC_SHE_UID_SZ, NULL),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    }
#endif

#if !defined(NO_WC_SHE_GETCOUNTER)
    {
        word32 cnt1 = 0;
        word32 cnt2 = 0;

        /* Callback should return incrementing counter */
        ExpectIntEQ(wc_SHE_GetCounter(&she, &cnt1, NULL), 0);
        ExpectIntEQ(wc_SHE_GetCounter(&she, &cnt2, NULL), 0);
        ExpectTrue(cnt2 > cnt1);

        /* Bad args */
        ExpectIntEQ(wc_SHE_GetCounter(NULL, &cnt1, NULL),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_SHE_GetCounter(&she, NULL, NULL),
                    WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    }
#endif

    wc_SHE_Free(&she);
    wc_CryptoCb_UnRegisterDevice(sheTestDevId);

    return EXPECT_RESULT();
}

#ifndef NO_WC_SHE_LOADKEY

int test_wc_SHE_LoadKey(void)
{
    EXPECT_DECLS;
    int sheTestDevId = 54322;
    byte m1[WC_SHE_M1_SZ];
    byte m2[WC_SHE_M2_SZ];
    byte m3[WC_SHE_M3_SZ];
    byte m4[WC_SHE_M4_SZ];
    byte m5[WC_SHE_M5_SZ];

    ExpectIntEQ(wc_CryptoCb_RegisterDevice(sheTestDevId,
                                            test_she_crypto_cb, NULL), 0);

    /* Generate valid M1/M2/M3 from test vectors */
    {
        wc_SHE she;
        ExpectIntEQ(wc_SHE_Init(&she, NULL, INVALID_DEVID), 0);
        ExpectIntEQ(wc_SHE_GenerateM1M2M3(&she,
                        sheTestUid, sizeof(sheTestUid),
                        WC_SHE_MASTER_ECU_KEY_ID,
                        sheTestAuthKey, sizeof(sheTestAuthKey),
                        4, sheTestNewKey, sizeof(sheTestNewKey), 1, 0,
                        m1, WC_SHE_M1_SZ, m2, WC_SHE_M2_SZ,
                        m3, WC_SHE_M3_SZ), 0);
        wc_SHE_Free(&she);
    }

    /* Basic: LoadKey should import M1/M2/M3 and produce M4/M5 via callback */
    ExpectIntEQ(wc_SHE_LoadKey(NULL, sheTestDevId,
                    m1, WC_SHE_M1_SZ, m2, WC_SHE_M2_SZ, m3, WC_SHE_M3_SZ,
                    m4, WC_SHE_M4_SZ, m5, WC_SHE_M5_SZ), 0);
    ExpectIntEQ(XMEMCMP(m4, sheTestExpM4, WC_SHE_M4_SZ), 0);
    ExpectIntEQ(XMEMCMP(m5, sheTestExpM5, WC_SHE_M5_SZ), 0);

    /* Bad args: NULL m1 */
    ExpectIntEQ(wc_SHE_LoadKey(NULL, sheTestDevId,
                    NULL, WC_SHE_M1_SZ, m2, WC_SHE_M2_SZ, m3, WC_SHE_M3_SZ,
                    m4, WC_SHE_M4_SZ, m5, WC_SHE_M5_SZ),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Bad args: NULL m4 output */
    ExpectIntEQ(wc_SHE_LoadKey(NULL, sheTestDevId,
                    m1, WC_SHE_M1_SZ, m2, WC_SHE_M2_SZ, m3, WC_SHE_M3_SZ,
                    NULL, WC_SHE_M4_SZ, m5, WC_SHE_M5_SZ),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Bad args: INVALID_DEVID */
    ExpectIntEQ(wc_SHE_LoadKey(NULL, INVALID_DEVID,
                    m1, WC_SHE_M1_SZ, m2, WC_SHE_M2_SZ, m3, WC_SHE_M3_SZ,
                    m4, WC_SHE_M4_SZ, m5, WC_SHE_M5_SZ),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Bad args: wrong M1 size */
    ExpectIntEQ(wc_SHE_LoadKey(NULL, sheTestDevId,
                    m1, WC_SHE_M1_SZ - 1, m2, WC_SHE_M2_SZ,
                    m3, WC_SHE_M3_SZ,
                    m4, WC_SHE_M4_SZ, m5, WC_SHE_M5_SZ),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_CryptoCb_UnRegisterDevice(sheTestDevId);
    return EXPECT_RESULT();
}

int test_wc_SHE_LoadKey_Verify(void)
{
    EXPECT_DECLS;
    int sheTestDevId = 54323;
    byte m1[WC_SHE_M1_SZ];
    byte m2[WC_SHE_M2_SZ];
    byte m3[WC_SHE_M3_SZ];
    byte m4[WC_SHE_M4_SZ];
    byte m5[WC_SHE_M5_SZ];
    byte badM4[WC_SHE_M4_SZ];

    ExpectIntEQ(wc_CryptoCb_RegisterDevice(sheTestDevId,
                                            test_she_crypto_cb, NULL), 0);

    /* Generate valid M1/M2/M3 from test vectors */
    {
        wc_SHE she;
        ExpectIntEQ(wc_SHE_Init(&she, NULL, INVALID_DEVID), 0);
        ExpectIntEQ(wc_SHE_GenerateM1M2M3(&she,
                        sheTestUid, sizeof(sheTestUid),
                        WC_SHE_MASTER_ECU_KEY_ID,
                        sheTestAuthKey, sizeof(sheTestAuthKey),
                        4, sheTestNewKey, sizeof(sheTestNewKey), 1, 0,
                        m1, WC_SHE_M1_SZ, m2, WC_SHE_M2_SZ,
                        m3, WC_SHE_M3_SZ), 0);
        wc_SHE_Free(&she);
    }

    /* Matching: expected M4/M5 match what the callback produces */
    ExpectIntEQ(wc_SHE_LoadKey_Verify(NULL, sheTestDevId,
                    m1, WC_SHE_M1_SZ, m2, WC_SHE_M2_SZ, m3, WC_SHE_M3_SZ,
                    m4, WC_SHE_M4_SZ, m5, WC_SHE_M5_SZ,
                    sheTestExpM4, WC_SHE_M4_SZ,
                    sheTestExpM5, WC_SHE_M5_SZ), 0);

    /* Mismatch: wrong expected M4 should fail with SIG_VERIFY_E */
    XMEMCPY(badM4, sheTestExpM4, WC_SHE_M4_SZ);
    badM4[0] ^= 0xFF;
    ExpectIntEQ(wc_SHE_LoadKey_Verify(NULL, sheTestDevId,
                    m1, WC_SHE_M1_SZ, m2, WC_SHE_M2_SZ, m3, WC_SHE_M3_SZ,
                    m4, WC_SHE_M4_SZ, m5, WC_SHE_M5_SZ,
                    badM4, WC_SHE_M4_SZ,
                    sheTestExpM5, WC_SHE_M5_SZ),
                WC_NO_ERR_TRACE(SIG_VERIFY_E));

    wc_CryptoCb_UnRegisterDevice(sheTestDevId);
    return EXPECT_RESULT();
}

#endif /* !NO_WC_SHE_LOADKEY */

#endif /* WOLF_CRYPTO_CB && WOLFSSL_SHE && !NO_AES */
