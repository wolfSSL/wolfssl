/* api_test_session_ticket.c
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
 *
 * Tests for TLS session ticket key rotation functionality.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef HAVE_SESSION_TICKET

#include <wolfssl/session_ticket_rotation.h>
#include <wolfssl/wolfcrypt/random.h>
#include <stdio.h>
#include <string.h>

/* Test master secret for key derivation */
static const unsigned char testMasterSecret[] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
};

/* Rotation callback tracking */
static int rotationCallbackCount = 0;
static int lastRotatedIndex = -1;

static void testRotationCallback(void* ctx, const unsigned char* keyName,
                                  int keyIndex)
{
    (void)ctx;
    (void)keyName;
    rotationCallbackCount++;
    lastRotatedIndex = keyIndex;
}

/* Test: Init and Free */
static int test_TicketKeyRotation_InitFree(void)
{
    TicketKeyRotationCtx ctx;
    int ret;

    printf("  Testing Init/Free...\n");

    ret = wolfSSL_TicketKeyRotation_Init(&ctx);
    if (ret != 0) {
        printf("    FAIL: Init returned %d\n", ret);
        return -1;
    }

    /* Verify default values */
    if (ctx.rotationInterval != WOLFSSL_TICKET_KEY_ROTATION_DEFAULT_INTERVAL) {
        printf("    FAIL: Default interval not set\n");
        return -2;
    }

    if (ctx.currentKeyIndex != -1) {
        printf("    FAIL: Initial key index should be -1\n");
        return -3;
    }

    if (!ctx.initialized) {
        printf("    FAIL: Should be initialized\n");
        return -4;
    }

    wolfSSL_TicketKeyRotation_Free(&ctx);

    if (ctx.initialized) {
        printf("    FAIL: Should not be initialized after free\n");
        return -5;
    }

    /* Test NULL argument */
    ret = wolfSSL_TicketKeyRotation_Init(NULL);
    if (ret != BAD_FUNC_ARG) {
        printf("    FAIL: Init(NULL) should return BAD_FUNC_ARG\n");
        return -6;
    }

    printf("    PASS\n");
    return 0;
}

/* Test: Set Master Secret */
static int test_TicketKeyRotation_SetMasterSecret(void)
{
    TicketKeyRotationCtx ctx;
    int ret;

    printf("  Testing SetMasterSecret...\n");

    ret = wolfSSL_TicketKeyRotation_Init(&ctx);
    if (ret != 0) return -1;

    ret = wolfSSL_TicketKeyRotation_SetMasterSecret(&ctx, testMasterSecret,
                                                     sizeof(testMasterSecret));
    if (ret != 0) {
        printf("    FAIL: SetMasterSecret returned %d\n", ret);
        wolfSSL_TicketKeyRotation_Free(&ctx);
        return -2;
    }

    if (ctx.masterSecretLen != (int)sizeof(testMasterSecret)) {
        printf("    FAIL: Master secret length mismatch\n");
        wolfSSL_TicketKeyRotation_Free(&ctx);
        return -3;
    }

    /* Test NULL arguments */
    ret = wolfSSL_TicketKeyRotation_SetMasterSecret(NULL, testMasterSecret,
                                                     sizeof(testMasterSecret));
    if (ret != BAD_FUNC_ARG) {
        printf("    FAIL: NULL ctx should return BAD_FUNC_ARG\n");
        wolfSSL_TicketKeyRotation_Free(&ctx);
        return -4;
    }

    ret = wolfSSL_TicketKeyRotation_SetMasterSecret(&ctx, NULL, 32);
    if (ret != BAD_FUNC_ARG) {
        printf("    FAIL: NULL secret should return BAD_FUNC_ARG\n");
        wolfSSL_TicketKeyRotation_Free(&ctx);
        return -5;
    }

    wolfSSL_TicketKeyRotation_Free(&ctx);
    printf("    PASS\n");
    return 0;
}

/* Test: Force Rotate and Get Active Key */
static int test_TicketKeyRotation_ForceRotate(void)
{
    TicketKeyRotationCtx ctx;
    TicketKeyEntry* key = NULL;
    int ret;

    printf("  Testing ForceRotate...\n");

    ret = wolfSSL_TicketKeyRotation_Init(&ctx);
    if (ret != 0) return -1;

    ret = wolfSSL_TicketKeyRotation_SetMasterSecret(&ctx, testMasterSecret,
                                                     sizeof(testMasterSecret));
    if (ret != 0) {
        wolfSSL_TicketKeyRotation_Free(&ctx);
        return -2;
    }

    /* Force first rotation */
    ret = wolfSSL_TicketKeyRotation_ForceRotate(&ctx);
    if (ret != 0) {
        printf("    FAIL: ForceRotate returned %d\n", ret);
        wolfSSL_TicketKeyRotation_Free(&ctx);
        return -3;
    }

    /* Verify we can get the active key */
    ret = wolfSSL_TicketKeyRotation_GetActiveKey(&ctx, &key);
    if (ret != 0 || key == NULL) {
        printf("    FAIL: GetActiveKey failed after rotation\n");
        wolfSSL_TicketKeyRotation_Free(&ctx);
        return -4;
    }

    if (!key->active) {
        printf("    FAIL: Key should be active\n");
        wolfSSL_TicketKeyRotation_Free(&ctx);
        return -5;
    }

    /* Verify key count */
    if (wolfSSL_TicketKeyRotation_GetKeyCount(&ctx) != 1) {
        printf("    FAIL: Key count should be 1\n");
        wolfSSL_TicketKeyRotation_Free(&ctx);
        return -6;
    }

    wolfSSL_TicketKeyRotation_Free(&ctx);
    printf("    PASS\n");
    return 0;
}

/* Test: Multiple rotations and key table management */
static int test_TicketKeyRotation_MultipleRotations(void)
{
    TicketKeyRotationCtx ctx;
    unsigned char prevKeyName[WOLFSSL_TICKET_KEY_NAME_SIZE];
    TicketKeyEntry* key = NULL;
    int ret, i;

    printf("  Testing multiple rotations...\n");

    ret = wolfSSL_TicketKeyRotation_Init(&ctx);
    if (ret != 0) return -1;

    ret = wolfSSL_TicketKeyRotation_SetMasterSecret(&ctx, testMasterSecret,
                                                     sizeof(testMasterSecret));
    if (ret != 0) {
        wolfSSL_TicketKeyRotation_Free(&ctx);
        return -2;
    }

    /* Perform multiple rotations */
    for (i = 0; i < WOLFSSL_TICKET_KEY_TABLE_SIZE + 2; i++) {
        ret = wolfSSL_TicketKeyRotation_ForceRotate(&ctx);
        if (ret != 0) {
            printf("    FAIL: Rotation %d failed with %d\n", i, ret);
            wolfSSL_TicketKeyRotation_Free(&ctx);
            return -3;
        }
    }

    /* Verify key count doesn't exceed table size */
    if (wolfSSL_TicketKeyRotation_GetKeyCount(&ctx) >
        WOLFSSL_TICKET_KEY_TABLE_SIZE) {
        printf("    FAIL: Key count exceeds table size\n");
        wolfSSL_TicketKeyRotation_Free(&ctx);
        return -4;
    }

    /* Verify each rotation produces a different key */
    ret = wolfSSL_TicketKeyRotation_GetActiveKey(&ctx, &key);
    if (ret != 0 || key == NULL) {
        wolfSSL_TicketKeyRotation_Free(&ctx);
        return -5;
    }
    XMEMCPY(prevKeyName, key->keyName, WOLFSSL_TICKET_KEY_NAME_SIZE);

    ret = wolfSSL_TicketKeyRotation_ForceRotate(&ctx);
    if (ret != 0) {
        wolfSSL_TicketKeyRotation_Free(&ctx);
        return -6;
    }

    ret = wolfSSL_TicketKeyRotation_GetActiveKey(&ctx, &key);
    if (ret != 0 || key == NULL) {
        wolfSSL_TicketKeyRotation_Free(&ctx);
        return -7;
    }

    if (XMEMCMP(prevKeyName, key->keyName, WOLFSSL_TICKET_KEY_NAME_SIZE) == 0) {
        printf("    FAIL: Rotation should produce different key names\n");
        wolfSSL_TicketKeyRotation_Free(&ctx);
        return -8;
    }

    wolfSSL_TicketKeyRotation_Free(&ctx);
    printf("    PASS\n");
    return 0;
}

/* Test: FindKeyByName */
static int test_TicketKeyRotation_FindKeyByName(void)
{
    TicketKeyRotationCtx ctx;
    TicketKeyEntry* key = NULL;
    TicketKeyEntry* foundKey = NULL;
    unsigned char keyName[WOLFSSL_TICKET_KEY_NAME_SIZE];
    int ret;

    printf("  Testing FindKeyByName...\n");

    ret = wolfSSL_TicketKeyRotation_Init(&ctx);
    if (ret != 0) return -1;

    ret = wolfSSL_TicketKeyRotation_SetMasterSecret(&ctx, testMasterSecret,
                                                     sizeof(testMasterSecret));
    if (ret != 0) {
        wolfSSL_TicketKeyRotation_Free(&ctx);
        return -2;
    }

    /* Create a key */
    ret = wolfSSL_TicketKeyRotation_ForceRotate(&ctx);
    if (ret != 0) {
        wolfSSL_TicketKeyRotation_Free(&ctx);
        return -3;
    }

    /* Get the active key name */
    ret = wolfSSL_TicketKeyRotation_GetActiveKey(&ctx, &key);
    if (ret != 0) {
        wolfSSL_TicketKeyRotation_Free(&ctx);
        return -4;
    }
    XMEMCPY(keyName, key->keyName, WOLFSSL_TICKET_KEY_NAME_SIZE);

    /* Find it by name */
    ret = wolfSSL_TicketKeyRotation_FindKeyByName(&ctx, keyName, &foundKey);
    if (ret != 0 || foundKey == NULL) {
        printf("    FAIL: FindKeyByName failed\n");
        wolfSSL_TicketKeyRotation_Free(&ctx);
        return -5;
    }

    if (XMEMCMP(foundKey->keyName, keyName, WOLFSSL_TICKET_KEY_NAME_SIZE) != 0) {
        printf("    FAIL: Found key name doesn't match\n");
        wolfSSL_TicketKeyRotation_Free(&ctx);
        return -6;
    }

    /* Try finding a non-existent key */
    XMEMSET(keyName, 0xFF, WOLFSSL_TICKET_KEY_NAME_SIZE);
    ret = wolfSSL_TicketKeyRotation_FindKeyByName(&ctx, keyName, &foundKey);
    if (ret == 0) {
        printf("    FAIL: Should not find non-existent key\n");
        wolfSSL_TicketKeyRotation_Free(&ctx);
        return -7;
    }

    wolfSSL_TicketKeyRotation_Free(&ctx);
    printf("    PASS\n");
    return 0;
}

/* Test: Rotation callback */
static int test_TicketKeyRotation_Callback(void)
{
    TicketKeyRotationCtx ctx;
    int ret;

    printf("  Testing rotation callback...\n");

    rotationCallbackCount = 0;
    lastRotatedIndex = -1;

    ret = wolfSSL_TicketKeyRotation_Init(&ctx);
    if (ret != 0) return -1;

    ret = wolfSSL_TicketKeyRotation_SetMasterSecret(&ctx, testMasterSecret,
                                                     sizeof(testMasterSecret));
    if (ret != 0) {
        wolfSSL_TicketKeyRotation_Free(&ctx);
        return -2;
    }

    ret = wolfSSL_TicketKeyRotation_SetCallback(&ctx, testRotationCallback,
                                                 NULL);
    if (ret != 0) {
        wolfSSL_TicketKeyRotation_Free(&ctx);
        return -3;
    }

    ret = wolfSSL_TicketKeyRotation_ForceRotate(&ctx);
    if (ret != 0) {
        wolfSSL_TicketKeyRotation_Free(&ctx);
        return -4;
    }

    if (rotationCallbackCount != 1) {
        printf("    FAIL: Callback should have been called once, got %d\n",
               rotationCallbackCount);
        wolfSSL_TicketKeyRotation_Free(&ctx);
        return -5;
    }

    if (lastRotatedIndex < 0) {
        printf("    FAIL: Callback should set valid index\n");
        wolfSSL_TicketKeyRotation_Free(&ctx);
        return -6;
    }

    /* Second rotation */
    ret = wolfSSL_TicketKeyRotation_ForceRotate(&ctx);
    if (ret != 0) {
        wolfSSL_TicketKeyRotation_Free(&ctx);
        return -7;
    }

    if (rotationCallbackCount != 2) {
        printf("    FAIL: Callback count should be 2, got %d\n",
               rotationCallbackCount);
        wolfSSL_TicketKeyRotation_Free(&ctx);
        return -8;
    }

    wolfSSL_TicketKeyRotation_Free(&ctx);
    printf("    PASS\n");
    return 0;
}

/* Test: Configuration setters */
static int test_TicketKeyRotation_Configuration(void)
{
    TicketKeyRotationCtx ctx;
    int ret;

    printf("  Testing configuration...\n");

    ret = wolfSSL_TicketKeyRotation_Init(&ctx);
    if (ret != 0) return -1;

    /* Set interval */
    ret = wolfSSL_TicketKeyRotation_SetInterval(&ctx, 7200);
    if (ret != 0 || ctx.rotationInterval != 7200) {
        printf("    FAIL: SetInterval failed\n");
        wolfSSL_TicketKeyRotation_Free(&ctx);
        return -2;
    }

    /* Set grace period */
    ret = wolfSSL_TicketKeyRotation_SetGracePeriod(&ctx, 1800);
    if (ret != 0 || ctx.gracePeriod != 1800) {
        printf("    FAIL: SetGracePeriod failed\n");
        wolfSSL_TicketKeyRotation_Free(&ctx);
        return -3;
    }

    /* Invalid interval */
    ret = wolfSSL_TicketKeyRotation_SetInterval(&ctx, 0);
    if (ret != BAD_FUNC_ARG) {
        printf("    FAIL: Zero interval should fail\n");
        wolfSSL_TicketKeyRotation_Free(&ctx);
        return -4;
    }

    wolfSSL_TicketKeyRotation_Free(&ctx);
    printf("    PASS\n");
    return 0;
}

/* Main test runner */
int test_session_ticket_rotation(void)
{
    int ret;

    printf("Session Ticket Rotation Tests:\n");

    ret = test_TicketKeyRotation_InitFree();
    if (ret != 0) return ret;

    ret = test_TicketKeyRotation_SetMasterSecret();
    if (ret != 0) return ret;

    ret = test_TicketKeyRotation_ForceRotate();
    if (ret != 0) return ret;

    ret = test_TicketKeyRotation_MultipleRotations();
    if (ret != 0) return ret;

    ret = test_TicketKeyRotation_FindKeyByName();
    if (ret != 0) return ret;

    ret = test_TicketKeyRotation_Callback();
    if (ret != 0) return ret;

    ret = test_TicketKeyRotation_Configuration();
    if (ret != 0) return ret;

    printf("All session ticket rotation tests passed!\n");
    return 0;
}

#endif /* HAVE_SESSION_TICKET */
