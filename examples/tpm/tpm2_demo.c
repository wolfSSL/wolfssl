/* tpm2-demo.c
 *
 * Copyright (C) 2006-2017 wolfSSL Inc.
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

#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/tpm2.h>
#include <wolfssl/wolfcrypt/logging.h>

#ifdef WOLFSSL_TPM2

/* Local variables */
static TPM2_CTX gTpm2Ctx;
#ifdef WOLFSSL_STM32_CUBEMX
    extern SPI_HandleTypeDef hspi1;
    #define TPM2_USER_CTX &hspi1
#else
    #define TPM2_USER_CTX NULL
#endif

/* IO Callback */
static TPM_RC TPM2_IoCb(TPM2_CTX* ctx, const byte* txBuf, byte* rxBuf,
    word16 xferSz, void* userCtx)
{
#ifdef WOLFSSL_STM32_CUBEMX
    SPI_HandleTypeDef* hspi = (SPI_HandleTypeDef*)userCtx;
    HAL_StatusTypeDef status;

    __HAL_SPI_ENABLE(hspi);
    status = HAL_SPI_TransmitReceive(hspi, (byte*)txBuf, rxBuf, xferSz, 5000);
    __HAL_SPI_DISABLE(hspi);
    if (status == HAL_OK)
        return TPM_RC_SUCCESS;

#else
    /* TODO: Add your platform here for HW interface */
    (void)ctx;
    (void)txBuf;
    (void)rxBuf;
    (void)xferSz;
    (void)userCtx;

#endif
    return TPM_RC_FAILURE;
}

#define RAND_GET_SZ 32

int TPM2_Demo(void)
{
    TPM_RC rc;
    union {
        Startup_In startup;
        Shutdown_In shutdown;
        SelfTest_In selfTest;
        GetRandom_In getRand;
        GetCapability_In cap;
        IncrementalSelfTest_In incSelfTest;
        PCR_Read_In pcrRead;
        PCR_Extend_In pcrExtend;
        Create_In create;
        Load_In load;
        FlushContext_In flushCtx;
        Unseal_In unseal;
        byte maxInput[MAX_COMMAND_SIZE];
    } cmdIn;
    union {
        GetCapability_Out cap;
        GetRandom_Out getRand;
        GetTestResult_Out tr;
        IncrementalSelfTest_Out incSelfTest;
        PCR_Read_Out pcrRead;
        Create_Out create;
        Load_Out load;
        Unseal_Out unseal;
        byte maxOutput[MAX_RESPONSE_SIZE];
    } cmdOut;
    int pcrCount, pcrIndex, i;
    TPML_TAGGED_TPM_PROPERTY* tpmProp;

#ifdef DEBUG_WOLFSSL
    wolfSSL_Debugging_ON();
#endif

    rc = TPM2_Init(&gTpm2Ctx, TPM2_IoCb, TPM2_USER_CTX);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_Init failed %d: %s\n", rc, TPM2_GetRCString(rc));
        return rc;
    }


    cmdIn.startup.startupType = TPM_SU_CLEAR;
    rc = TPM2_Startup(&cmdIn.startup);
    if (rc != TPM_RC_SUCCESS &&
        rc != TPM_RC_INITIALIZE /* TPM_RC_INITIALIZE = Already started */ ) {
        printf("TPM2_Startup failed %d: %s\n", rc, TPM2_GetRCString(rc));
        return rc;
    }
    printf("TPM2_Startup pass\n");


    /* Full self test */
    cmdIn.selfTest.fullTest = YES;
    rc = TPM2_SelfTest(&cmdIn.selfTest);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_SelfTest failed %d: %s\n", rc, TPM2_GetRCString(rc));
        return rc;
    }
    printf("TPM2_SelfTest pass\n");

    /* Get Test Result */
    rc = TPM2_GetTestResult(&cmdOut.tr);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_GetTestResult failed %d: %s\n", rc, TPM2_GetRCString(rc));
        return rc;
    }
    printf("TPM2_GetTestResult: Size %d, Rc 0x%x\n", cmdOut.tr.outData.size,
        cmdOut.tr.testResult);
    WOLFSSL_BUFFER(cmdOut.tr.outData.buffer, cmdOut.tr.outData.size);

    /* Incremental Test */
    cmdIn.incSelfTest.toTest.count = 1;
    cmdIn.incSelfTest.toTest.algorithms[0] = TPM_ALG_RSA;
	rc = TPM2_IncrementalSelfTest(&cmdIn.incSelfTest, &cmdOut.incSelfTest);
	printf("TPM2_IncrementalSelfTest: Rc 0x%x, Alg 0x%x (Todo %d)\n",
			rc, cmdIn.incSelfTest.toTest.algorithms[0],
            (int)cmdOut.incSelfTest.toDoList.count);


    /* Get Capability for Property */
    cmdIn.cap.capability = TPM_CAP_TPM_PROPERTIES;
    cmdIn.cap.property = TPM_PT_FAMILY_INDICATOR;
    cmdIn.cap.propertyCount = 1;
    rc = TPM2_GetCapability(&cmdIn.cap, &cmdOut.cap);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_GetCapability failed %d: %s\n", rc, TPM2_GetRCString(rc));
        return rc;
    }
    tpmProp = &cmdOut.cap.capabilityData.data.tpmProperties;
    printf("TPM2_GetCapability: Property FamilyIndicator 0x%08x\n",
        (unsigned int)tpmProp->tpmProperty[0].value);

    cmdIn.cap.capability = TPM_CAP_TPM_PROPERTIES;
    cmdIn.cap.property = TPM_PT_PCR_COUNT;
    cmdIn.cap.propertyCount = 1;
    rc = TPM2_GetCapability(&cmdIn.cap, &cmdOut.cap);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_GetCapability failed %d: %s\n", rc, TPM2_GetRCString(rc));
        return rc;
    }
    tpmProp = &cmdOut.cap.capabilityData.data.tpmProperties;
    pcrCount = tpmProp->tpmProperty[0].value;
    printf("TPM2_GetCapability: Property PCR Count %d\n", pcrCount);


    /* Random */
    cmdIn.getRand.bytesRequested = RAND_GET_SZ;
    rc = TPM2_GetRandom(&cmdIn.getRand, &cmdOut.getRand);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_GetRandom failed %d: %s\n", rc, TPM2_GetRCString(rc));
        return rc;
    }
    if (cmdOut.getRand.randomBytes.size != RAND_GET_SZ) {
        printf("TPM2_GetRandom length mismatch %d != %d\n",
            cmdOut.getRand.randomBytes.size, RAND_GET_SZ);
        return rc;
    }
    printf("TPM2_GetRandom: Got %d bytes\n", cmdOut.getRand.randomBytes.size);
    WOLFSSL_BUFFER(cmdOut.getRand.randomBytes.buffer,
                   cmdOut.getRand.randomBytes.size);


    /* PCR Read */
    for (i=0; i<pcrCount; i++) {
        pcrIndex = i;
        TPM2_SetupPCRSel(&cmdIn.pcrRead.pcrSelectionIn, TPM_ALG_SHA256, pcrIndex);
        rc = TPM2_PCR_Read(&cmdIn.pcrRead, &cmdOut.pcrRead);
        if (rc != TPM_RC_SUCCESS) {
            printf("TPM2_PCR_Read failed %d: %s\n", rc, TPM2_GetRCString(rc));
            return rc;
        }
        printf("TPM2_PCR_Read: Index %d, Digest Sz %d, Update Counter %d\n",
            pcrIndex,
            (int)cmdOut.pcrRead.pcrValues.digests[0].size,
            (int)cmdOut.pcrRead.pcrUpdateCounter);
        WOLFSSL_BUFFER(cmdOut.pcrRead.pcrValues.digests[0].buffer,
                       cmdOut.pcrRead.pcrValues.digests[0].size);
    }

    /* PCR Extend and Verify */
    pcrIndex = 0;
    XMEMSET(&cmdIn.pcrExtend, 0, sizeof(cmdIn.pcrExtend));
    cmdIn.pcrExtend.pcrHandle = pcrIndex;
    cmdIn.pcrExtend.auth.sessionHandle = TPM_RS_PW;
    cmdIn.pcrExtend.digests.count = 1;
    cmdIn.pcrExtend.digests.digests[0].hashAlg = TPM_ALG_SHA256;
    for (i=0; i<WC_SHA256_DIGEST_SIZE; i++) {
        cmdIn.pcrExtend.digests.digests[0].digest.H[i] = i;
    }
    rc = TPM2_PCR_Extend(&cmdIn.pcrExtend);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_PCR_Extend failed %d: %s\n", rc, TPM2_GetRCString(rc));
        return rc;
    }
    TPM2_SetupPCRSel(&cmdIn.pcrRead.pcrSelectionIn, TPM_ALG_SHA256, pcrIndex);
    rc = TPM2_PCR_Read(&cmdIn.pcrRead, &cmdOut.pcrRead);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_PCR_Read failed %d: %s\n", rc, TPM2_GetRCString(rc));
        return rc;
    }
    printf("TPM2_PCR_Read: Index %d, Digest Sz %d, Update Counter %d\n",
        pcrIndex,
        (int)cmdOut.pcrRead.pcrValues.digests[0].size,
        (int)cmdOut.pcrRead.pcrUpdateCounter);
    WOLFSSL_BUFFER(cmdOut.pcrRead.pcrValues.digests[0].buffer,
                   cmdOut.pcrRead.pcrValues.digests[0].size);


    /* TODO: Add tests for API's */
    //TPM_RC TPM2_Create(Create_In* in, Create_Out* out)
    //TPM_RC TPM2_Load(Load_In* in, Load_Out* out);
    //TPM_RC TPM2_FlushContext(FlushContext_In* in);
    //TPM_RC TPM2_Unseal(Unseal_In* in, Unseal_Out* out);


    /* Shutdown */
    cmdIn.shutdown.shutdownType = TPM_SU_CLEAR;
    rc = TPM2_Shutdown(&cmdIn.shutdown);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_Shutdown failed %d: %s\n", rc, TPM2_GetRCString(rc));
        return rc;
    }

    return rc;
}

#endif /* WOLFSSL_TPM2 */
