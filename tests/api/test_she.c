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

#include <wolfssl/wolfcrypt/she.h>
#include <wolfssl/wolfcrypt/types.h>
#ifdef WOLF_CRYPTO_CB
    #include <wolfssl/wolfcrypt/cryptocb.h>
#endif
#include <tests/api/api.h>
#include <tests/api/test_she.h>

/*
 * Testing wc_SHE_Init()
 */
int test_wc_SHE_Init(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHE) && !defined(NO_AES)
    wc_SHE she;

    /* Valid init with default heap/devId */
    ExpectIntEQ(wc_SHE_Init(&she, NULL, INVALID_DEVID), 0);

    /* Verify heap and devId are stored correctly */
    ExpectTrue(she.heap == NULL);
    ExpectIntEQ(she.devId, INVALID_DEVID);

    /* Verify state flags are zeroed */
    ExpectIntEQ(she.generated, 0);
    ExpectIntEQ(she.verified, 0);

    /* Verify key material is zeroed */
    {
        byte zeros[WC_SHE_KEY_SZ] = {0};
        ExpectIntEQ(XMEMCMP(she.authKey, zeros, WC_SHE_KEY_SZ), 0);
        ExpectIntEQ(XMEMCMP(she.newKey, zeros, WC_SHE_KEY_SZ), 0);
    }

    wc_SHE_Free(&she);

    /* Test bad args: NULL pointer */
    ExpectIntEQ(wc_SHE_Init(NULL, NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    return EXPECT_RESULT();
} /* END test_wc_SHE_Init */

/*
 * Testing wc_SHE_Free()
 */
int test_wc_SHE_Free(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHE) && !defined(NO_AES)
    wc_SHE she;

    /* Init, then free — should scrub key material */
    ExpectIntEQ(wc_SHE_Init(&she, NULL, INVALID_DEVID), 0);
    wc_SHE_Free(&she);

    /* After free, context should be zeroed */
    ExpectIntEQ(she.devId, 0);
    ExpectIntEQ(she.generated, 0);
    ExpectIntEQ(she.verified, 0);

    /* Free with NULL should not crash */
    wc_SHE_Free(NULL);
#endif
    return EXPECT_RESULT();
} /* END test_wc_SHE_Free */

/*
 * Testing wc_SHE_Init_Id()
 */
int test_wc_SHE_Init_Id(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHE) && !defined(NO_AES) && defined(WOLF_PRIVATE_KEY_ID)
    wc_SHE she;
    unsigned char testId[] = {0x01, 0x02, 0x03, 0x04};

    /* Valid init with a 4-byte key ID */
    ExpectIntEQ(wc_SHE_Init_Id(&she, testId, (int)sizeof(testId),
                                NULL, INVALID_DEVID), 0);

    /* Verify the ID was copied and length is set */
    ExpectIntEQ(she.idLen, (int)sizeof(testId));
    ExpectIntEQ(XMEMCMP(she.id, testId, sizeof(testId)), 0);

    /* Verify label length is cleared */
    ExpectIntEQ(she.labelLen, 0);

    /* Verify heap and devId are stored */
    ExpectTrue(she.heap == NULL);
    ExpectIntEQ(she.devId, INVALID_DEVID);

    wc_SHE_Free(&she);

    /* Test bad args: NULL she pointer */
    ExpectIntEQ(wc_SHE_Init_Id(NULL, testId, (int)sizeof(testId),
                                NULL, INVALID_DEVID),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test bad args: ID length too large */
    ExpectIntEQ(wc_SHE_Init_Id(&she, testId, WC_SHE_MAX_ID_LEN + 1,
                                NULL, INVALID_DEVID),
                WC_NO_ERR_TRACE(BUFFER_E));

    /* Test bad args: negative ID length */
    ExpectIntEQ(wc_SHE_Init_Id(&she, testId, -1, NULL, INVALID_DEVID),
                WC_NO_ERR_TRACE(BUFFER_E));

    /* Test zero-length ID is valid */
    ExpectIntEQ(wc_SHE_Init_Id(&she, testId, 0, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(she.idLen, 0);
    wc_SHE_Free(&she);
#endif
    return EXPECT_RESULT();
} /* END test_wc_SHE_Init_Id */

/*
 * Testing wc_SHE_Init_Label()
 */
int test_wc_SHE_Init_Label(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHE) && !defined(NO_AES) && defined(WOLF_PRIVATE_KEY_ID)
    wc_SHE she;
    const char* testLabel = "my_she_key";

    /* Valid init with a label string */
    ExpectIntEQ(wc_SHE_Init_Label(&she, testLabel, NULL, INVALID_DEVID), 0);

    /* Verify the label was copied and length is set */
    ExpectIntEQ(she.labelLen, (int)XSTRLEN(testLabel));
    ExpectIntEQ(XMEMCMP(she.label, testLabel, XSTRLEN(testLabel)), 0);

    /* Verify ID length is cleared */
    ExpectIntEQ(she.idLen, 0);

    /* Verify heap and devId are stored */
    ExpectTrue(she.heap == NULL);
    ExpectIntEQ(she.devId, INVALID_DEVID);

    wc_SHE_Free(&she);

    /* Test bad args: NULL she pointer */
    ExpectIntEQ(wc_SHE_Init_Label(NULL, testLabel, NULL, INVALID_DEVID),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test bad args: NULL label */
    ExpectIntEQ(wc_SHE_Init_Label(&she, NULL, NULL, INVALID_DEVID),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test bad args: empty label */
    ExpectIntEQ(wc_SHE_Init_Label(&she, "", NULL, INVALID_DEVID),
                WC_NO_ERR_TRACE(BUFFER_E));
#endif
    return EXPECT_RESULT();
} /* END test_wc_SHE_Init_Label */

/*
 * Testing wc_SHE_SetUID()
 */
int test_wc_SHE_SetUID(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHE) && !defined(NO_AES)
    wc_SHE she;
    byte uid[WC_SHE_UID_SZ] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    };

    ExpectIntEQ(wc_SHE_Init(&she, NULL, INVALID_DEVID), 0);

    /* Valid UID */
    ExpectIntEQ(wc_SHE_SetUID(&she, uid, WC_SHE_UID_SZ, NULL), 0);
    ExpectIntEQ(XMEMCMP(she.uid, uid, WC_SHE_UID_SZ), 0);

    /* Bad args */
    ExpectIntEQ(wc_SHE_SetUID(NULL, uid, WC_SHE_UID_SZ, NULL),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SHE_SetUID(&she, NULL, WC_SHE_UID_SZ, NULL),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SHE_SetUID(&she, uid, WC_SHE_UID_SZ - 1, NULL),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SHE_SetUID(&she, uid, WC_SHE_UID_SZ + 1, NULL),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_SHE_Free(&she);
#endif
    return EXPECT_RESULT();
} /* END test_wc_SHE_SetUID */

/*
 * Testing wc_SHE_SetAuthKey()
 */
int test_wc_SHE_SetAuthKey(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHE) && !defined(NO_AES)
    wc_SHE she;
    byte key[WC_SHE_KEY_SZ] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    ExpectIntEQ(wc_SHE_Init(&she, NULL, INVALID_DEVID), 0);

    /* Valid auth key */
    ExpectIntEQ(wc_SHE_SetAuthKey(&she, WC_SHE_MASTER_ECU_KEY_ID,
                                   key, WC_SHE_KEY_SZ), 0);
    ExpectIntEQ(she.authKeyId, WC_SHE_MASTER_ECU_KEY_ID);
    ExpectIntEQ(XMEMCMP(she.authKey, key, WC_SHE_KEY_SZ), 0);

    /* Bad args */
    ExpectIntEQ(wc_SHE_SetAuthKey(NULL, 0, key, WC_SHE_KEY_SZ),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SHE_SetAuthKey(&she, 0, NULL, WC_SHE_KEY_SZ),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SHE_SetAuthKey(&she, 0, key, WC_SHE_KEY_SZ - 1),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_SHE_Free(&she);
#endif
    return EXPECT_RESULT();
} /* END test_wc_SHE_SetAuthKey */

/*
 * Testing wc_SHE_SetNewKey()
 */
int test_wc_SHE_SetNewKey(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHE) && !defined(NO_AES)
    wc_SHE she;
    byte key[WC_SHE_KEY_SZ] = {
        0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00
    };

    ExpectIntEQ(wc_SHE_Init(&she, NULL, INVALID_DEVID), 0);

    /* Valid new key */
    ExpectIntEQ(wc_SHE_SetNewKey(&she, 4, key, WC_SHE_KEY_SZ), 0);
    ExpectIntEQ(she.targetKeyId, 4);
    ExpectIntEQ(XMEMCMP(she.newKey, key, WC_SHE_KEY_SZ), 0);

    /* Bad args */
    ExpectIntEQ(wc_SHE_SetNewKey(NULL, 4, key, WC_SHE_KEY_SZ),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SHE_SetNewKey(&she, 4, NULL, WC_SHE_KEY_SZ),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SHE_SetNewKey(&she, 4, key, 0),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_SHE_Free(&she);
#endif
    return EXPECT_RESULT();
} /* END test_wc_SHE_SetNewKey */

/*
 * Testing wc_SHE_SetCounter()
 */
int test_wc_SHE_SetCounter(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHE) && !defined(NO_AES)
    wc_SHE she;

    ExpectIntEQ(wc_SHE_Init(&she, NULL, INVALID_DEVID), 0);

    ExpectIntEQ(wc_SHE_SetCounter(&she, 1), 0);
    ExpectIntEQ(she.counter, 1);

    ExpectIntEQ(wc_SHE_SetCounter(&she, 0x0FFFFFFF), 0);
    ExpectIntEQ(she.counter, 0x0FFFFFFF);

    /* Bad args */
    ExpectIntEQ(wc_SHE_SetCounter(NULL, 1),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_SHE_Free(&she);
#endif
    return EXPECT_RESULT();
} /* END test_wc_SHE_SetCounter */

/*
 * Testing wc_SHE_SetFlags()
 */
int test_wc_SHE_SetFlags(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHE) && !defined(NO_AES)
    wc_SHE she;

    ExpectIntEQ(wc_SHE_Init(&she, NULL, INVALID_DEVID), 0);

    ExpectIntEQ(wc_SHE_SetFlags(&she, 0), 0);
    ExpectIntEQ(she.flags, 0);

    ExpectIntEQ(wc_SHE_SetFlags(&she, WC_SHE_FLAG_WRITE_PROTECT |
                                       WC_SHE_FLAG_BOOT_PROTECT), 0);
    ExpectIntEQ(she.flags, WC_SHE_FLAG_WRITE_PROTECT |
                            WC_SHE_FLAG_BOOT_PROTECT);

    /* Bad args */
    ExpectIntEQ(wc_SHE_SetFlags(NULL, 0),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_SHE_Free(&she);
#endif
    return EXPECT_RESULT();
} /* END test_wc_SHE_SetFlags */

/*
 * Testing wc_SHE_SetKdfConstants()
 */
int test_wc_SHE_SetKdfConstants(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHE) && !defined(NO_AES)
    wc_SHE she;
    const byte defEncC[] = WC_SHE_KEY_UPDATE_ENC_C;
    const byte defMacC[] = WC_SHE_KEY_UPDATE_MAC_C;
    byte customEncC[WC_SHE_KEY_SZ];
    byte customMacC[WC_SHE_KEY_SZ];

    ExpectIntEQ(wc_SHE_Init(&she, NULL, INVALID_DEVID), 0);

    /* Init should set defaults */
    ExpectIntEQ(XMEMCMP(she.kdfEncC, defEncC, WC_SHE_KEY_SZ), 0);
    ExpectIntEQ(XMEMCMP(she.kdfMacC, defMacC, WC_SHE_KEY_SZ), 0);

    /* Override both */
    XMEMCPY(customEncC, defEncC, WC_SHE_KEY_SZ);
    XMEMCPY(customMacC, defMacC, WC_SHE_KEY_SZ);
    customEncC[1] += 0x80;
    customMacC[1] += 0x80;
    ExpectIntEQ(wc_SHE_SetKdfConstants(&she,
                    customEncC, WC_SHE_KEY_SZ,
                    customMacC, WC_SHE_KEY_SZ), 0);
    ExpectIntEQ(XMEMCMP(she.kdfEncC, customEncC, WC_SHE_KEY_SZ), 0);
    ExpectIntEQ(XMEMCMP(she.kdfMacC, customMacC, WC_SHE_KEY_SZ), 0);

    /* Override only encC, leave macC unchanged */
    ExpectIntEQ(wc_SHE_SetKdfConstants(&she,
                    defEncC, WC_SHE_KEY_SZ, NULL, 0), 0);
    ExpectIntEQ(XMEMCMP(she.kdfEncC, defEncC, WC_SHE_KEY_SZ), 0);
    ExpectIntEQ(XMEMCMP(she.kdfMacC, customMacC, WC_SHE_KEY_SZ), 0);

    /* Bad args: NULL she */
    ExpectIntEQ(wc_SHE_SetKdfConstants(NULL,
                    defEncC, WC_SHE_KEY_SZ, defMacC, WC_SHE_KEY_SZ),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Bad args: wrong size */
    ExpectIntEQ(wc_SHE_SetKdfConstants(&she,
                    defEncC, WC_SHE_KEY_SZ - 1, NULL, 0),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_SHE_Free(&she);
#endif
    return EXPECT_RESULT();
} /* END test_wc_SHE_SetKdfConstants */

/*
 * Testing wc_SHE_SetM2Header() and wc_SHE_SetM4Header()
 */
int test_wc_SHE_SetM2M4Header(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHE) && !defined(NO_AES)
    wc_SHE she, sheOvr;
    byte uid[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    };
    byte authKey[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    byte newKey[] = {
        0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00
    };
    byte customHeader[WC_SHE_KEY_SZ] = {0};
    byte m1Def[WC_SHE_M1_SZ], m2Def[WC_SHE_M2_SZ], m3Def[WC_SHE_M3_SZ];
    byte m1Ovr[WC_SHE_M1_SZ], m2Ovr[WC_SHE_M2_SZ], m3Ovr[WC_SHE_M3_SZ];

    /* --- SetM2Header bad args --- */
    ExpectIntEQ(wc_SHE_SetM2Header(NULL, customHeader, WC_SHE_KEY_SZ),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SHE_SetM4Header(NULL, customHeader, WC_SHE_KEY_SZ),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_SHE_Init(&she, NULL, INVALID_DEVID), 0);

    /* NULL header */
    ExpectIntEQ(wc_SHE_SetM2Header(&she, NULL, WC_SHE_KEY_SZ),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Wrong size */
    ExpectIntEQ(wc_SHE_SetM2Header(&she, customHeader, WC_SHE_KEY_SZ - 1),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SHE_SetM4Header(&she, customHeader, WC_SHE_KEY_SZ + 1),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Valid set */
    XMEMSET(customHeader, 0xAA, WC_SHE_KEY_SZ);
    ExpectIntEQ(wc_SHE_SetM2Header(&she, customHeader, WC_SHE_KEY_SZ), 0);
    ExpectIntEQ(XMEMCMP(she.m2pHeader, customHeader, WC_SHE_KEY_SZ), 0);
    ExpectIntEQ(she.m2pOverride, 1);

    ExpectIntEQ(wc_SHE_SetM4Header(&she, customHeader, WC_SHE_KEY_SZ), 0);
    ExpectIntEQ(XMEMCMP(she.m4pHeader, customHeader, WC_SHE_KEY_SZ), 0);
    ExpectIntEQ(she.m4pOverride, 1);

    wc_SHE_Free(&she);

    /* --- Override produces different M2 than default --- */
    /* Default path: counter=1, flags=0, auto-built headers */
    ExpectIntEQ(wc_SHE_Init(&she, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_SHE_SetUID(&she, uid, sizeof(uid), NULL), 0);
    ExpectIntEQ(wc_SHE_SetAuthKey(&she, 1, authKey, sizeof(authKey)), 0);
    ExpectIntEQ(wc_SHE_SetNewKey(&she, 4, newKey, sizeof(newKey)), 0);
    ExpectIntEQ(wc_SHE_SetCounter(&she, 1), 0);
    ExpectIntEQ(wc_SHE_SetFlags(&she, 0), 0);
    ExpectIntEQ(wc_SHE_GenerateM1M2M3(&she), 0);
    ExpectIntEQ(wc_SHE_ExportKey(&she,
                    m1Def, WC_SHE_M1_SZ, m2Def, WC_SHE_M2_SZ,
                    m3Def, WC_SHE_M3_SZ, NULL, 0, NULL, 0, NULL), 0);
    wc_SHE_Free(&she);

    /* Override path: same inputs but custom m2pHeader */
    ExpectIntEQ(wc_SHE_Init(&sheOvr, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_SHE_SetUID(&sheOvr, uid, sizeof(uid), NULL), 0);
    ExpectIntEQ(wc_SHE_SetAuthKey(&sheOvr, 1, authKey, sizeof(authKey)), 0);
    ExpectIntEQ(wc_SHE_SetNewKey(&sheOvr, 4, newKey, sizeof(newKey)), 0);
    ExpectIntEQ(wc_SHE_SetCounter(&sheOvr, 1), 0);
    ExpectIntEQ(wc_SHE_SetFlags(&sheOvr, 0), 0);
    /* Set a different header ΓÇö should produce different M2/M3 */
    XMEMSET(customHeader, 0, WC_SHE_KEY_SZ);
    customHeader[0] = 0xFF;  /* different from auto-built */
    ExpectIntEQ(wc_SHE_SetM2Header(&sheOvr, customHeader, WC_SHE_KEY_SZ), 0);
    ExpectIntEQ(wc_SHE_GenerateM1M2M3(&sheOvr), 0);
    ExpectIntEQ(wc_SHE_ExportKey(&sheOvr,
                    m1Ovr, WC_SHE_M1_SZ, m2Ovr, WC_SHE_M2_SZ,
                    m3Ovr, WC_SHE_M3_SZ, NULL, 0, NULL, 0, NULL), 0);

    /* M1 should be same (UID|IDs unchanged), M2 should differ */
    ExpectIntEQ(XMEMCMP(m1Def, m1Ovr, WC_SHE_M1_SZ), 0);
    ExpectIntNE(XMEMCMP(m2Def, m2Ovr, WC_SHE_M2_SZ), 0);

    wc_SHE_Free(&sheOvr);
#endif
    return EXPECT_RESULT();
} /* END test_wc_SHE_SetM2M4Header */

/*
 * Testing wc_SHE_GenerateM1M2M3()
 */
int test_wc_SHE_GenerateM1M2M3(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHE) && !defined(NO_AES)
    wc_SHE she;
    byte uid[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    };
    byte authKey[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    byte newKey[] = {
        0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00
    };

    ExpectIntEQ(wc_SHE_Init(&she, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_SHE_SetUID(&she, uid, sizeof(uid), NULL), 0);
    ExpectIntEQ(wc_SHE_SetAuthKey(&she, WC_SHE_MASTER_ECU_KEY_ID,
                                   authKey, sizeof(authKey)), 0);
    ExpectIntEQ(wc_SHE_SetNewKey(&she, 4, newKey, sizeof(newKey)), 0);
    ExpectIntEQ(wc_SHE_SetCounter(&she, 1), 0);
    ExpectIntEQ(wc_SHE_SetFlags(&she, 0), 0);

    /* Generate should succeed and set generated flag */
    ExpectIntEQ(wc_SHE_GenerateM1M2M3(&she), 0);
    ExpectIntEQ(she.generated, 1);

    /* Bad args */
    ExpectIntEQ(wc_SHE_GenerateM1M2M3(NULL),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_SHE_Free(&she);
#endif
    return EXPECT_RESULT();
} /* END test_wc_SHE_GenerateM1M2M3 */

/*
 * Testing wc_She_AesMp16() — Miyaguchi-Preneel compression
 */
int test_wc_She_AesMp16(void)
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
    /* 17 bytes — not block-aligned, triggers zero-padding path */
    byte shortInput[17] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0xAA
    };

    ExpectIntEQ(wc_AesInit(&aes, NULL, INVALID_DEVID), 0);

    /* Valid block-aligned input */
    ExpectIntEQ(wc_She_AesMp16(&aes, input, sizeof(input), out), 0);

    /* Non-block-aligned input — exercises zero-padding */
    ExpectIntEQ(wc_AesInit(&aes, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_She_AesMp16(&aes, shortInput, sizeof(shortInput), out), 0);

    /* Bad args: NULL aes */
    ExpectIntEQ(wc_She_AesMp16(NULL, input, sizeof(input), out),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Bad args: NULL input */
    ExpectIntEQ(wc_She_AesMp16(&aes, NULL, sizeof(input), out),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Bad args: zero size */
    ExpectIntEQ(wc_She_AesMp16(&aes, input, 0, out),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Bad args: NULL output */
    ExpectIntEQ(wc_She_AesMp16(&aes, input, sizeof(input), NULL),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_AesFree(&aes);
#endif
    return EXPECT_RESULT();
} /* END test_wc_She_AesMp16 */

/*
 * Testing wc_SHE_ExportKey()
 */
int test_wc_SHE_ExportKey(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHE) && !defined(NO_AES)
    wc_SHE she;
    byte m1[WC_SHE_M1_SZ];
    byte m2[WC_SHE_M2_SZ];
    byte m3[WC_SHE_M3_SZ];
    byte m4[WC_SHE_M4_SZ];
    byte m5[WC_SHE_M5_SZ];
    byte uid[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    };
    byte authKey[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    byte newKey[] = {
        0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00
    };

    ExpectIntEQ(wc_SHE_Init(&she, NULL, INVALID_DEVID), 0);

    /* Export before generate should return BAD_STATE_E */
    ExpectIntEQ(wc_SHE_ExportKey(&she,
                    m1, WC_SHE_M1_SZ, NULL, 0, NULL, 0,
                    NULL, 0, NULL, 0, NULL),
                WC_NO_ERR_TRACE(BAD_STATE_E));

    /* NULL she should return BAD_FUNC_ARG */
    ExpectIntEQ(wc_SHE_ExportKey(NULL,
                    m1, WC_SHE_M1_SZ, NULL, 0, NULL, 0,
                    NULL, 0, NULL, 0, NULL),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Set up, generate, and compute verification */
    ExpectIntEQ(wc_SHE_SetUID(&she, uid, sizeof(uid), NULL), 0);
    ExpectIntEQ(wc_SHE_SetAuthKey(&she, WC_SHE_MASTER_ECU_KEY_ID,
                                   authKey, sizeof(authKey)), 0);
    ExpectIntEQ(wc_SHE_SetNewKey(&she, 4, newKey, sizeof(newKey)), 0);
    ExpectIntEQ(wc_SHE_SetCounter(&she, 1), 0);
    ExpectIntEQ(wc_SHE_SetFlags(&she, 0), 0);
    ExpectIntEQ(wc_SHE_GenerateM1M2M3(&she), 0);
    ExpectIntEQ(wc_SHE_GenerateM4M5(&she), 0);

    /* Export only M1/M2/M3 */
    ExpectIntEQ(wc_SHE_ExportKey(&she,
                    m1, WC_SHE_M1_SZ,
                    m2, WC_SHE_M2_SZ,
                    m3, WC_SHE_M3_SZ,
                    NULL, 0, NULL, 0, NULL), 0);

    /* Export only M4/M5 */
    ExpectIntEQ(wc_SHE_ExportKey(&she,
                    NULL, 0, NULL, 0, NULL, 0,
                    m4, WC_SHE_M4_SZ,
                    m5, WC_SHE_M5_SZ, NULL), 0);

    /* Export all M1-M5 */
    ExpectIntEQ(wc_SHE_ExportKey(&she,
                    m1, WC_SHE_M1_SZ,
                    m2, WC_SHE_M2_SZ,
                    m3, WC_SHE_M3_SZ,
                    m4, WC_SHE_M4_SZ,
                    m5, WC_SHE_M5_SZ, NULL), 0);

    /* Buffer too small */
    ExpectIntEQ(wc_SHE_ExportKey(&she,
                    m1, 1, NULL, 0, NULL, 0,
                    NULL, 0, NULL, 0, NULL),
                WC_NO_ERR_TRACE(BUFFER_E));

    /* Export M4/M5 when generated but not verified — BAD_STATE_E */
    {
        wc_SHE badShe;
        ExpectIntEQ(wc_SHE_Init(&badShe, NULL, INVALID_DEVID), 0);
        badShe.generated = 1;  /* fake generated state */
        badShe.verified  = 0;  /* but not verified */
        ExpectIntEQ(wc_SHE_ExportKey(&badShe,
                        NULL, 0, NULL, 0, NULL, 0,
                        m4, WC_SHE_M4_SZ,
                        NULL, 0, NULL),
                    WC_NO_ERR_TRACE(BAD_STATE_E));
        wc_SHE_Free(&badShe);
    }

    wc_SHE_Free(&she);
#endif
    return EXPECT_RESULT();
} /* END test_wc_SHE_ExportKey */

/*
 * Testing wc_SHE_GenerateM4M5()
 */
int test_wc_SHE_GenerateM4M5(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHE) && !defined(NO_AES)
    wc_SHE she;
    byte uid[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    };
    byte authKey[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    byte newKey[] = {
        0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00
    };

    ExpectIntEQ(wc_SHE_Init(&she, NULL, INVALID_DEVID), 0);

    /* GenerateM4M5 before GenerateM1M2M3 should return BAD_STATE_E */
    ExpectIntEQ(wc_SHE_GenerateM4M5(&she),
                WC_NO_ERR_TRACE(BAD_STATE_E));

    /* Set up and generate M1/M2/M3 */
    ExpectIntEQ(wc_SHE_SetUID(&she, uid, sizeof(uid), NULL), 0);
    ExpectIntEQ(wc_SHE_SetAuthKey(&she, WC_SHE_MASTER_ECU_KEY_ID,
                                   authKey, sizeof(authKey)), 0);
    ExpectIntEQ(wc_SHE_SetNewKey(&she, 4, newKey, sizeof(newKey)), 0);
    ExpectIntEQ(wc_SHE_SetCounter(&she, 1), 0);
    ExpectIntEQ(wc_SHE_SetFlags(&she, 0), 0);
    ExpectIntEQ(wc_SHE_GenerateM1M2M3(&she), 0);

    /* Now compute M4/M5 */
    ExpectIntEQ(wc_SHE_GenerateM4M5(&she), 0);
    ExpectIntEQ(she.verified, 1);

    /* Bad args */
    ExpectIntEQ(wc_SHE_GenerateM4M5(NULL),
                WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    wc_SHE_Free(&she);
#endif
    return EXPECT_RESULT();
} /* END test_wc_SHE_GenerateM4M5 */

#if defined(WOLF_CRYPTO_CB) && defined(WOLFSSL_SHE) && !defined(NO_AES)

/* Simple SHE callback that falls back to software by resetting devId */
static int test_she_crypto_cb(int devIdArg, wc_CryptoInfo* info, void* ctx)
{
    int ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    wc_SHE* she;
    int savedDevId;

    (void)ctx;
    (void)devIdArg;

    if (info == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLF_CRYPTO_CB_FREE
    /* Handle free callback */
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
        case WC_SHE_SET_UID:
            ret = wc_SHE_SetUID(she, info->she.op.setUid.uid,
                                 info->she.op.setUid.uidSz,
                                 info->she.ctx);
            break;
        case WC_SHE_GENERATE_M4M5:
            ret = wc_SHE_GenerateM4M5(she);
            break;
        case WC_SHE_EXPORT_KEY:
            ret = wc_SHE_ExportKey(she,
                      info->she.op.exportKey.m1,
                      info->she.op.exportKey.m1Sz,
                      info->she.op.exportKey.m2,
                      info->she.op.exportKey.m2Sz,
                      info->she.op.exportKey.m3,
                      info->she.op.exportKey.m3Sz,
                      info->she.op.exportKey.m4,
                      info->she.op.exportKey.m4Sz,
                      info->she.op.exportKey.m5,
                      info->she.op.exportKey.m5Sz,
                      info->she.ctx);
            break;
        default:
            ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
            break;
    }

    she->devId = savedDevId;
    return ret;
}

/*
 * Testing SHE callback path for SetUID and GenerateM4M5
 */
int test_wc_SHE_CryptoCb(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_SHE) && !defined(NO_AES)
    wc_SHE she;
    int sheTestDevId = 54321;
    byte m4[WC_SHE_M4_SZ];
    byte m5[WC_SHE_M5_SZ];
    byte uid[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    };
    byte authKey[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    byte newKey[] = {
        0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00
    };

    /* Register our test callback with a non-INVALID devId */
    ExpectIntEQ(wc_CryptoCb_RegisterDevice(sheTestDevId,
                                            test_she_crypto_cb, NULL), 0);

    /* Init with the test devId so callback path is used */
    ExpectIntEQ(wc_SHE_Init(&she, NULL, sheTestDevId), 0);

    /* SetUID via callback — passes uid through to software */
    ExpectIntEQ(wc_SHE_SetUID(&she, uid, sizeof(uid), NULL), 0);
    ExpectIntEQ(XMEMCMP(she.uid, uid, WC_SHE_UID_SZ), 0);

    /* Set remaining inputs (software only) */
    ExpectIntEQ(wc_SHE_SetAuthKey(&she, WC_SHE_MASTER_ECU_KEY_ID,
                                   authKey, sizeof(authKey)), 0);
    ExpectIntEQ(wc_SHE_SetNewKey(&she, 4, newKey, sizeof(newKey)), 0);
    ExpectIntEQ(wc_SHE_SetCounter(&she, 1), 0);
    ExpectIntEQ(wc_SHE_SetFlags(&she, 0), 0);

    /* GenerateLoadKey — software, callback not involved */
    ExpectIntEQ(wc_SHE_GenerateM1M2M3(&she), 0);

    /* GenerateM4M5 via callback — falls back to software */
    ExpectIntEQ(wc_SHE_GenerateM4M5(&she), 0);
    ExpectIntEQ(she.verified, 1);

    /* ExportKey via callback path */
    ExpectIntEQ(wc_SHE_ExportKey(&she,
                    NULL, 0, NULL, 0, NULL, 0,
                    m4, WC_SHE_M4_SZ,
                    m5, WC_SHE_M5_SZ, NULL), 0);

    /* Export all M1-M5 via callback */
    {
        byte cm1[WC_SHE_M1_SZ];
        byte cm2[WC_SHE_M2_SZ];
        byte cm3[WC_SHE_M3_SZ];
        ExpectIntEQ(wc_SHE_ExportKey(&she,
                        cm1, WC_SHE_M1_SZ,
                        cm2, WC_SHE_M2_SZ,
                        cm3, WC_SHE_M3_SZ,
                        m4, WC_SHE_M4_SZ,
                        m5, WC_SHE_M5_SZ, NULL), 0);
    }

    wc_SHE_Free(&she);
    wc_CryptoCb_UnRegisterDevice(sheTestDevId);
#endif
    return EXPECT_RESULT();
} /* END test_wc_SHE_CryptoCb */

#endif /* WOLF_CRYPTO_CB && WOLFSSL_SHE && !NO_AES */

