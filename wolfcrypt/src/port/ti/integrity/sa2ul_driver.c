/* sa2ul_driver.c
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

/* Kernel-linked AES + SHA driver for the AM64x SA2UL crypto accelerator.
 *
 * This is not a completely fresh implementation.  It is mostly a
 * port of TI's mcu_plus_sdk_am64x SA2UL driver.  Hooks to the SDK UDMA engine
 * were replaced by calls to the j7_dma/j7_sci API in the INTEGRITY jacinto7
 * BSP.
 *
 * All DMA-visible state (rings, descriptors, security context and a bounce
 * buffer) lives in memory from MemorySpace_AllocateDmaMemory(). Requests
 * arrive from sa2ul_iodevice_server.c; operations are synchronous and
 * polled, one at a time.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

#include <INTEGRITY.h>
#include <INTEGRITY_intrinsics.h>
#include <bsp.h>
#include <support/memoryspace.h>

#include <driver/soc/jacinto7/j7_dma.h>
#include <driver/soc/jacinto7/j7_dma_spec.h>
#include <driver/soc/jacinto7/j7_sci.h>

#include <wolfssl/wolfcrypt/port/ti/integrity/sa2ul_driver.h>

#include <console_logging.h>
#define SA2UL_LOG console_printf

#define SA2UL_NO_TRACE

#ifndef SA2UL_NO_TRACE
    #define SA2UL_TRACE(step) console_printf("sa2ul: %s\n", step)
#else
    #define SA2UL_TRACE(step) do { } while (0)
#endif

#ifndef DIM
    #define DIM(a) (sizeof(a) / sizeof((a)[0]))
#endif
#ifndef ROUNDUP
    #define ROUNDUP(x, a) ((((x) + (a) - 1u) / (a)) * (a))
#endif

/* CP_ACE base = 0x40900000 register space */
#define CP_ACE_MMR_EFUSE_EN_OFFSET          0x04u
#define CP_ACE_MMR_CMD_STATUS_OFFSET        0x08u
#define CP_ACE_UPDATES_ENGINE_ENABLE_OFFSET 0x1000u

#define CP_ACE_EFUSE_EN_ENABLE_BIT          0x1u
#define CP_ACE_ENCSS_EN_MASK                0x1u
#define CP_ACE_AUTHSS_EN_MASK               0x2u
#define CP_ACE_CTX_EN_MASK                  0x80u
#define CP_ACE_CDMA_IN_EN_MASK              0x200u
#define CP_ACE_CDMA_OUT_EN_MASK             0x800u
#define SA2UL_ENGINE_MASK (CP_ACE_ENCSS_EN_MASK | CP_ACE_AUTHSS_EN_MASK | \
        CP_ACE_CTX_EN_MASK | CP_ACE_CDMA_IN_EN_MASK | CP_ACE_CDMA_OUT_EN_MASK)

static volatile uint8_t *gCpAceBase = NULL;
#define CPACE_REG32(off) (*(volatile uint32_t *)(gCpAceBase + (off)))

static int sa2ul_engine_enable(void)
{
#ifndef SA2UL_ENGINE_CONTROL
    (void)gCpAceBase;
    return 0;
#else
    uint32_t efuse, reg;
    unsigned int timeout;

    efuse = CPACE_REG32(CP_ACE_MMR_EFUSE_EN_OFFSET);
    if ((efuse & CP_ACE_EFUSE_EN_ENABLE_BIT) == 0u) {
        SA2UL_LOG("sa2ul_driver: engine not enabled by efuse (EFUSE_EN=0x%08lx)\n",
                (unsigned long)efuse);
        return -1;
    }

    /* On AM64x the engines are normally already enabled via optee and
     * ENGINE_ENABLE may be firewalled from the A53, so only touch it when
     * something we need is actually off. */
    reg = CPACE_REG32(CP_ACE_MMR_CMD_STATUS_OFFSET);
    if ((reg & SA2UL_ENGINE_MASK) == SA2UL_ENGINE_MASK) {
        return 0;
    }
    SA2UL_LOG("sa2ul_driver: CMD_STATUS=0x%08lx, enabling engines\n",
            (unsigned long)reg);

    reg = CPACE_REG32(CP_ACE_UPDATES_ENGINE_ENABLE_OFFSET);
    reg |= SA2UL_ENGINE_MASK;
    CPACE_REG32(CP_ACE_UPDATES_ENGINE_ENABLE_OFFSET) = reg;

    for (timeout = 0; timeout < 1000000u; timeout++) {
        if ((CPACE_REG32(CP_ACE_MMR_CMD_STATUS_OFFSET) & SA2UL_ENGINE_MASK)
                == SA2UL_ENGINE_MASK) {
            return 0;
        }
    }
    SA2UL_LOG("sa2ul_driver: engine enable timed out (CMD_STATUS=0x%08lx)\n",
            (unsigned long)CPACE_REG32(CP_ACE_MMR_CMD_STATUS_OFFSET));
    return -1;
#endif /* SA2UL_ENGINE_CONTROL */
}

/* CPPI5 host-mode packet descriptor and SA2UL's own extension of it */
struct Cppi5HostDescr {
    uint32_t descInfo;
    uint32_t pktInfo1;
    uint32_t pktInfo2;
    uint32_t srcDstTag;
    uint64_t nextDescPtr;
    uint64_t bufPtr;
    uint32_t bufInfo1;
    uint32_t orgBufLen;
    uint64_t orgBufPtr;
};

struct Sa2ulExtendedPktInfo {
    uint32_t timestamp;
    uint32_t swWord0;
    uint32_t scptrL;
    uint32_t scptrH;
} __attribute__((__packed__));

struct Sa2ulPsDataTx {
    uint32_t inPsiInfo;
    uint32_t cmdLblHdr1;
    uint32_t cmdLblHdr2;
    uint32_t optionWords[52 / 4];
} __attribute__((__packed__));

struct Sa2ulPsDataRx {
    uint32_t trailerData[16];
} __attribute__((__packed__));

struct Sa2ulHostDescrTx {
    struct Cppi5HostDescr pd;
    struct Sa2ulExtendedPktInfo exPktInfo;
    struct Sa2ulPsDataTx psData;
} __attribute__((__packed__));

struct Sa2ulHostDescrRx {
    struct Cppi5HostDescr pd;
    struct Sa2ulExtendedPktInfo exPktInfo;
    struct Sa2ulPsDataRx psData;
} __attribute__((__packed__));

/* similar to CSL_* from the TI mcu plus sdk... */
#define FLD(val, shift, mask) ((((uint32_t)(val)) << (shift)) & (mask))
#define FEXT(reg, shift, mask) ((((uint32_t)(reg)) & (mask)) >> (shift))

#define UDMAP_CPPI5_PD_DESCINFO_DTYPE_SHIFT        30u
#define UDMAP_CPPI5_PD_DESCINFO_DTYPE_MASK         0xC0000000u
#define CPPI5_PD_DESCINFO_DTYPE_VAL_HOST           1u
#define UDMAP_CPPI5_PD_DESCINFO_EINFO_SHIFT        29u
#define UDMAP_CPPI5_PD_DESCINFO_EINFO_MASK         0x20000000u
#define CPPI5_PD_DESCINFO_EINFO_VAL_IS_PRESENT     1u
#define UDMAP_CPPI5_PD_DESCINFO_PSWCNT_SHIFT       22u
#define UDMAP_CPPI5_PD_DESCINFO_PSWCNT_MASK        0x0FC00000u
#define UDMAP_CPPI5_PD_DESCINFO_PKTLEN_SHIFT       0u
#define UDMAP_CPPI5_PD_DESCINFO_PKTLEN_MASK        0x003FFFFFu
#define PKTDMA_CPPI5_PD_DESCINFO_PSWCNT_SHIFT      UDMAP_CPPI5_PD_DESCINFO_PSWCNT_SHIFT
#define PKTDMA_CPPI5_PD_DESCINFO_PSWCNT_MASK       UDMAP_CPPI5_PD_DESCINFO_PSWCNT_MASK
#define PKTDMA_CPPI5_PD_DESCINFO_PKTLEN_SHIFT      UDMAP_CPPI5_PD_DESCINFO_PKTLEN_SHIFT
#define PKTDMA_CPPI5_PD_DESCINFO_PKTLEN_MASK       UDMAP_CPPI5_PD_DESCINFO_PKTLEN_MASK

#define UDMAP_CPPI5_PD_PKTINFO1_FLOWID_SHIFT       0u
#define UDMAP_CPPI5_PD_PKTINFO1_FLOWID_MASK        0x00003FFFu
#define UDMAP_CPPI5_PD_PKTINFO1_PSFLGS_SHIFT       24u
#define UDMAP_CPPI5_PD_PKTINFO1_PSFLGS_MASK        0x0F000000u

#define UDMAP_CPPI5_PD_PKTINFO2_RETQ_SHIFT         0u
#define UDMAP_CPPI5_PD_PKTINFO2_RETQ_MASK          0x0000ffffu

#define SA2UL_SWWORD0_BYP_CMD_LBL_LEN_SHIFT        31u
#define SA2UL_SWWORD0_BYP_CMD_LBL_LEN_MASK         0x80000000u
#define SA2UL_SWWORD0_CPPI_DST_INFO_PRESENT_SHIFT  30u
#define SA2UL_SWWORD0_CPPI_DST_INFO_PRESENT_MASK   0x40000000u
#define SA2UL_SWWORD0_ENGINE_ID_SHIFT              25u
#define SA2UL_SWWORD0_ENGINE_ID_MASK               0x3e000000u
#define SA2UL_SWWORD0_CMD_LBL_PRESENT_SHIFT        24u
#define SA2UL_SWWORD0_CMD_LBL_PRESENT_MASK         0x1000000u
#define SA2UL_SWWORD0_CMD_LBL_OFFSET_SHIFT         20u
#define SA2UL_SWWORD0_CMD_LBL_OFFSET_MASK          0xf00000u
#define SA2UL_SWWORD0_FRAGMENT_SHIFT               19u
#define SA2UL_SWWORD0_FRAGMENT_MASK                0x80000u
#define SA2UL_SWWORD0_TEARDOWN_SHIFT               17u
#define SA2UL_SWWORD0_TEARDOWN_MASK                0x20000u
#define SA2UL_SWWORD0_EVICT_SHIFT                  16u
#define SA2UL_SWWORD0_EVICT_MASK                   0x10000u
#define SA2UL_SWWORD0_SCID_SHIFT                   0u
#define SA2UL_SWWORD0_SCID_MASK                    0xffffu

#define SA2UL_SCPTRH_EGRESS_CPPI_STATUS_LEN_SHIFT  24u
#define SA2UL_SCPTRH_EGRESS_CPPI_STATUS_LEN_MASK   0xff000000u

#define SA2UL_INPSIINFO_EGRESS_CPPI_DEST_QUEUE_NUM_SHIFT 16u
#define SA2UL_INPSIINFO_EGRESS_CPPI_DEST_QUEUE_NUM_MASK  0xffff0000u

#define SA2UL_CMDLBLHDR1_LEN_TO_BE_PROCESSESED_SHIFT 0u
#define SA2UL_CMDLBLHDR1_LEN_TO_BE_PROCESSESED_MASK  0xffffu
#define SA2UL_CMDLBLHDR1_CMD_LABEL_LEN_SHIFT       16u
#define SA2UL_CMDLBLHDR1_CMD_LABEL_LEN_MASK        0xff0000u
#define SA2UL_CMDLBLHDR1_NEXT_ENGINE_SELECT_CODE_SHIFT 24u
#define SA2UL_CMDLBLHDR1_NEXT_ENGINE_SELECT_CODE_MASK  0xff000000u

#define SA2UL_CMDLBLHDR2_OPTION1_CTX_OFFSET_SHIFT  19u
#define SA2UL_CMDLBLHDR2_OPTION1_CTX_OFFSET_MASK   0xf80000u
#define SA2UL_CMDLBLHDR2_OPTION1_LEN_SHIFT         16u
#define SA2UL_CMDLBLHDR2_OPTION1_LEN_MASK          0x70000u

#define SA2UL_SCCTL1_OWNER_SHIFT                   31u
#define SA2UL_SCCTL1_OWNER_MASK                    0x80000000u
#define SA2UL_SCCTL1_EVICT_DONE_SHIFT               30u
#define SA2UL_SCCTL1_EVICT_DONE_MASK                0x40000000u
#define SA2UL_SCCTL1_FETCH_EVICT_CONTROL_SHIFT      16u
#define SA2UL_SCCTL1_FETCH_EVICT_CONTROL_MASK       0xff0000u

#define SA2UL_SCCTL2_PRIVID_SHIFT                  16u
#define SA2UL_SCCTL2_PRIVID_MASK                   0xff0000u
#define SA2UL_SCCTL2_PRIV_SHIFT                    8u
#define SA2UL_SCCTL2_PRIV_MASK                     0x300u
#define SA2UL_SCCTL2_SECURE_SHIFT                  0u
#define SA2UL_SCCTL2_SECURE_MASK                   0x1u

#define SA2UL_AUTHCTX1_MODESEL_SHIFT                31u
#define SA2UL_AUTHCTX1_MODESEL_MASK                 0x80000000u
#define SA2UL_AUTHCTX1_DEFAULT_NEXT_ENGINE_ID_SHIFT 24u
#define SA2UL_AUTHCTX1_DEFAULT_NEXT_ENGINE_ID_MASK  0x1f000000u
#define SA2UL_AUTHCTX1_SW_CONTROL_SHIFT             16u
#define SA2UL_AUTHCTX1_SW_CONTROL_MASK              0xff0000u

#define SA2UL_ENCRCTL_MODESEL_SHIFT                31u
#define SA2UL_ENCRCTL_MODESEL_MASK                 0x80000000u
#define SA2UL_ENCRCTL_USE_DKEK_SHIFT                30u
#define SA2UL_ENCRCTL_USE_DKEK_MASK                 0x40000000u
#define SA2UL_ENCRCTL_DEFAULT_NEXT_ENGINE_ID_SHIFT  24u
#define SA2UL_ENCRCTL_DEFAULT_NEXT_ENGINE_ID_MASK   0x1f000000u
#define SA2UL_ENCRCTL_TRAILER_EVERY_CHUNK_SHIFT     23u
#define SA2UL_ENCRCTL_TRAILER_EVERY_CHUNK_MASK      0x800000u
#define SA2UL_ENCRCTL_TRAILER_AT_END_SHIFT          22u
#define SA2UL_ENCRCTL_TRAILER_AT_END_MASK           0x400000u
#define SA2UL_ENCRCTL_PKT_DATA_SECTION_UPDATE_SHIFT 21u
#define SA2UL_ENCRCTL_PKT_DATA_SECTION_UPDATE_MASK  0x200000u
#define SA2UL_ENCRCTL_ENCRYPT_DECRYPT_SHIFT         20u
#define SA2UL_ENCRCTL_ENCRYPT_DECRYPT_MASK          0x100000u
#define SA2UL_ENCRCTL_BLK_SIZE_SHIFT                16u
#define SA2UL_ENCRCTL_BLK_SIZE_MASK                 0x70000u
#define SA2UL_ENCRCTL_SOP_OFFSET_SHIFT              8u
#define SA2UL_ENCRCTL_SOP_OFFSET_MASK               0xF00u
#define SA2UL_ENCRCTL_MIDDLE_OFFSET_SHIFT           4u
#define SA2UL_ENCRCTL_MIDDLE_OFFSET_MASK            0xF0u
#define SA2UL_ENCRCTL_EOP_OFFSET_SHIFT              0u
#define SA2UL_ENCRCTL_EOP_OFFSET_MASK               0xFu

#define SA2UL_ENGINE_CODE_ENCRYPTION_MODULE_P1     2u
#define SA2UL_ENGINE_CODE_AUTHENTICATION_MODULE_P1 4u
#define SA2UL_ENGINE_CODE_DEFAULT_EGRESS_PORT      20u
#define SA2UL_OP_ENC                0x01u
#define SA2UL_OP_AUTH               0x02u
#define SA2UL_ENC_ALG_AES           0x0u
#define SA2UL_ENC_DIR_ENCRYPT       0x0u
#define SA2UL_ENC_DIR_DECRYPT       0x1u
#define SA2UL_ENC_MODE_ECB          0x0u
#define SA2UL_ENC_MODE_CBC          0x1u
#define SA2UL_ENC_MODE_GCM          0x2u
#define SA2UL_ENC_KEYSIZE_128       0x0u
#define SA2UL_ENC_KEYSIZE_192       0x1u
#define SA2UL_ENC_KEYSIZE_256       0x2u
#define SA2UL_ENC_KEYSIZE_BITS(k) (128u + (64u * (k)))

#define SA2UL_MAX_KEY_SIZE_BYTES    32u
#define SA2UL_MAX_IV_SIZE_BYTES     16u
#define SA2UL_MAX_IV_SIZE_BYTES_GCM 12u
#define SA2UL_MAX_AAD_SIZE_BYTES    16u
#define SA2UL_GHASH_LENGTH_BYTES    16u
#define SA2UL_AES_GCM_AUTHTAG_SIZE_IN_BYTES 16u
#define SA2UL_MAX_INPUT_LENGTH_ENC  0xFFFFu
#define SA2UL_PSIL_DST_THREAD_OFFSET 0x8000u

#define SA2UL_HASH_ALG_SHA1         0x12u
#define SA2UL_HASH_ALG_SHA2_224     0x13u
#define SA2UL_HASH_ALG_SHA2_256     0x14u
#define SA2UL_HASH_ALG_SHA2_384     0x15u
#define SA2UL_HASH_ALG_SHA2_512     0x16u
#define SA2UL_MAX_HASH_SIZE_BYTES   64u
#define SA2UL_MAX_INPUT_LENGTH_AUTH 0x3FFFFFu

/* bit 4 clear means HMAC, set means plain hash */
#define SA2UL_IS_HMAC(alg) (((alg) & 0x10u) == 0u)

/* indexed by hashAlg & 7u...
 *  SHA1=0x12->2, SHA2_224=0x13->3, SHA2_256=0x14->4, SHA2_384=0x15->5,
 *  SHA2_512=0x16->6 (indices 0/1/7 are not used by this port) */
static const uint32_t gSa2ulHashSizeBytes[8] = {
    0u, 16u, 20u, 28u, 32u, 48u, 64u, 0u
};

/* This driver's own AES-only view of TI's SA2UL_ContextParams */
struct Sa2ulAesParams {
    uint8_t  encDirection;
    uint8_t  encMode;
    uint8_t  key[SA2UL_MAX_KEY_SIZE_BYTES];
    uint8_t  encKeySize;
    uint32_t inputLen;
    uint8_t  iv[SA2UL_MAX_IV_SIZE_BYTES];
    uint8_t  aad[SA2UL_MAX_AAD_SIZE_BYTES];
    uint8_t  ghash[SA2UL_GHASH_LENGTH_BYTES];
    uint32_t aadLen;
};

/* ctx for aes */
struct Sa2ulSecCtxEnc {
    uint32_t encrCtl;
    uint32_t modeCtrlInstrs[6];
    uint32_t hwCtrlWord;
    uint32_t encKeyValue[8];
    uint32_t encAux1[8];
    uint32_t encAux2[4];
    uint32_t encAux3[4];
    uint32_t encAux4[4];
    uint8_t  preCryptoData[15];
};

/* ctx for sha */
struct Sa2ulSecCtxAuth {
    uint32_t authCtx1;
    uint32_t reserved0;
    uint32_t authenticationLengthHi;
    uint32_t authenticationLengthLo;
    uint32_t reserved1[4];
    uint32_t authenticationKeyValueL[8];
    uint32_t oPadL[8];
    uint32_t authenticationKeyValueH[8];
    uint32_t oPadH[8];
};

struct Sa2ulScctl {
    uint32_t scctl1;
    uint32_t scctl2;
    uint32_t scptrH;
    uint32_t scptrL;
};

struct Sa2ulSecCtx {
    struct Sa2ulScctl scctl;
    uint32_t unused[12];
    union {
        struct Sa2ulSecCtxAuth auth;
        struct Sa2ulSecCtxEnc  enc;
    } u;
};

/* Covers both ops this port supports (SA2UL_OP_ENC/SA2UL_OP_AUTH) */
struct Sa2ulContext {
    struct Sa2ulSecCtx     secCtx;
    uint8_t                secCtxId;
    uint8_t                opType;
    uint8_t                hashAlg;
    struct Sa2ulAesParams  prms;
    uint32_t               totalLengthInBytes;
};

/* Mode-control-engine microcode tables
 *  References in the TI SDK sa2ul.c: gSa2ulMceAes*[], gSa2ulMceDataArray[],
 *  MCE_PACK2(), SA2UL_EncBlksizeEncoded[], SA2UL_getMceIndex()) */

#define MCE_PACK2(op1, f21, f11, f01, op2, f22, f12, f02) \
        ((op1) << 4) | ((f21) << 2) | ((f11) >> 1), \
        (((f11) & 1) << 7) | ((f01) << 4) | (op2), \
        ((f22) << 6) | ((f12) << 3) | (f02)

static const uint8_t SA2UL_EncBlksizeEncoded[2] = { 1u, 0u }; /* [SA2UL_ENC_ALG_AES]=1 */

static const uint8_t gSa2ulMceAes256CbcEncr[] = {
    MCE_PACK2(1, 0, 1, 0,   8, 2, 1, 0),
    MCE_PACK2(10, 2, 4, 4,  11, 1, 7, 6)
};
static const uint8_t gSa2ulMceAes256CbcDecr[] = {
    MCE_PACK2(8, 2, 1, 0,   10, 3, 1, 2),
    MCE_PACK2(9, 2, 1, 7,   4, 1, 0, 0),
    MCE_PACK2(12, 0, 0, 0,  0, 0, 0, 0)
};
static const uint8_t gSa2ulMceAes256Ecb[] = {
    MCE_PACK2(8, 2, 1, 0,   10, 0, 0, 4),
    MCE_PACK2(11, 1, 7, 1,  0, 0, 0, 0)
};
static const uint8_t gSa2ulMceAes128CbcDecr[] = {
    MCE_PACK2(8, 0, 1, 0,   10, 3, 1, 2),
    MCE_PACK2(9, 2, 1, 7,   4, 1, 0, 0),
    MCE_PACK2(12, 0, 0, 0,  0, 0, 0, 0)
};
static const uint8_t gSa2ulMceAes128CbcEncr[] = {
    MCE_PACK2(1, 0, 1, 0,   8, 0, 1, 0),
    MCE_PACK2(10, 2, 4, 4,  11, 1, 7, 6)
};
static const uint8_t gSa2ulMceAes128Ecb[] = {
    MCE_PACK2(8, 0, 1, 0,   10, 0, 0, 4),
    MCE_PACK2(11, 1, 7, 1,  0, 0, 0, 0)
};
static const uint8_t gSa2ulMceAes256GcmEncr[] = {
 0x88, 0xa9, 0xfe, 0x83, 0x99, 0x7e, 0x58, 0x2e, 0x8a, 0x90, 0x71, 0x41,
 0x83, 0x9d, 0x63, 0xaa, 0x0b, 0x7e, 0x9a, 0x78, 0x3a, 0xa3, 0x8b, 0x1e
};
static const uint8_t gSa2ulMceAes256GcmDecr[] = {
 0x88, 0xa9, 0xfe, 0x83, 0x99, 0x7e, 0x58, 0x2e, 0x8a, 0x14, 0x19, 0x07,
 0x83, 0x9d, 0x63, 0xaa, 0x0b, 0x7e, 0x9a, 0x78, 0x3a, 0xa3, 0x8b, 0x1e
};
static const uint8_t gSa2ulMceAes128GcmEncr[] = {
 0x80, 0xa9, 0xfe, 0x83, 0x99, 0x7e, 0x58, 0x2e, 0x0a, 0x90, 0x71, 0x41,
 0x83, 0x9d, 0x63, 0xaa, 0x0b, 0x7e, 0x9a, 0x78, 0x3a, 0xa3, 0x8b, 0x1e
};
static const uint8_t gSa2ulMceAes192CbcEncr[] = {
    MCE_PACK2(1, 0, 1, 0,   8, 1, 1, 0),
    MCE_PACK2(10, 2, 4, 4,  11, 1, 7, 6)
};
static const uint8_t gSa2ulMceAes192CbcDecr[] = {
    MCE_PACK2(8, 1, 1, 0,   10, 3, 1, 2),
    MCE_PACK2(9, 2, 1, 7,   4, 1, 0, 0),
    MCE_PACK2(12, 0, 0, 0,  0, 0, 0, 0)
};
static const uint8_t gSa2ulMceAes192Ecb[] = {
    MCE_PACK2(8, 1, 1, 0,   10, 0, 0, 4),
    MCE_PACK2(11, 1, 7, 1,  0, 0, 0, 0)
};
static const uint8_t gSa2ulMceAes192GcmEncr[] = {
 0x84, 0xa9, 0xfe, 0x83, 0x99, 0x7e, 0x58, 0x2e, 0x4a, 0x90, 0x71, 0x41,
 0x83, 0x9d, 0x63, 0xaa, 0x0b, 0x7e, 0x9a, 0x78, 0x3a, 0xa3, 0x8b, 0x1e
};
static const uint8_t gSa2ulMceAes192GcmDecr[] = {
 0x84, 0xa9, 0xfe, 0x83, 0x99, 0x7e, 0x58, 0x2e, 0x4a, 0x14, 0x19, 0x07,
 0x83, 0x9d, 0x63, 0xaa, 0x0b, 0x7e, 0x9a, 0x78, 0x3a, 0xa3, 0x8b, 0x1e
};
static const uint8_t gSa2ulMceAes128GcmDecr[] = {
 0x80, 0xa9, 0xfe, 0x83, 0x99, 0x7e, 0x58, 0x2e, 0x0a, 0x14, 0x19, 0x07,
 0x83, 0x9d, 0x63, 0xaa, 0x0b, 0x7e, 0x9a, 0x78, 0x3a, 0xa3, 0x8b, 0x1e
};

struct Sa2ulMceData {
    uint8_t sopOffset, middleOffset, eopOffset;
    uint8_t nMCInstrs;
    const uint8_t *mcInstrs;
};

enum {
    MCE_IDX_AES_256_ECB = 0, MCE_IDX_AES_256_CBC_ENCRYPT, MCE_IDX_AES_256_CBC_DECRYPT,
    MCE_IDX_AES_128_ECB, MCE_IDX_AES_128_CBC_ENCRYPT, MCE_IDX_AES_128_CBC_DECRYPT,
    MCE_IDX_AES_256_GCM_ENCRYPT, MCE_IDX_AES_256_GCM_DECRYPT,
    MCE_IDX_AES_128_GCM_ENCRYPT, MCE_IDX_AES_128_GCM_DECRYPT,
    MCE_IDX_AES_192_ECB, MCE_IDX_AES_192_CBC_ENCRYPT, MCE_IDX_AES_192_CBC_DECRYPT,
    MCE_IDX_AES_192_GCM_ENCRYPT, MCE_IDX_AES_192_GCM_DECRYPT,
    MCE_IDX_COUNT
};

static const struct Sa2ulMceData gSa2ulMceDataArray[MCE_IDX_COUNT] = {
    { 0, 0, 0, sizeof(gSa2ulMceAes256Ecb),      gSa2ulMceAes256Ecb },
    { 0, 0, 0, sizeof(gSa2ulMceAes256CbcEncr),  gSa2ulMceAes256CbcEncr },
    { 0, 0, 0, sizeof(gSa2ulMceAes256CbcDecr),  gSa2ulMceAes256CbcDecr },
    { 0, 0, 0, sizeof(gSa2ulMceAes128Ecb),      gSa2ulMceAes128Ecb },
    { 0, 0, 0, sizeof(gSa2ulMceAes128CbcEncr),  gSa2ulMceAes128CbcEncr },
    { 0, 0, 0, sizeof(gSa2ulMceAes128CbcDecr),  gSa2ulMceAes128CbcDecr },
    { 0, 4, 4, sizeof(gSa2ulMceAes256GcmEncr),  gSa2ulMceAes256GcmEncr },
    { 0, 4, 4, sizeof(gSa2ulMceAes256GcmDecr),  gSa2ulMceAes256GcmDecr },
    { 0, 4, 4, sizeof(gSa2ulMceAes128GcmEncr),  gSa2ulMceAes128GcmEncr },
    { 0, 4, 4, sizeof(gSa2ulMceAes128GcmDecr),  gSa2ulMceAes128GcmDecr },
    { 0, 0, 0, sizeof(gSa2ulMceAes192Ecb),      gSa2ulMceAes192Ecb },
    { 0, 0, 0, sizeof(gSa2ulMceAes192CbcEncr),  gSa2ulMceAes192CbcEncr },
    { 0, 0, 0, sizeof(gSa2ulMceAes192CbcDecr),  gSa2ulMceAes192CbcDecr },
    { 0, 4, 4, sizeof(gSa2ulMceAes192GcmEncr),  gSa2ulMceAes192GcmEncr },
    { 0, 4, 4, sizeof(gSa2ulMceAes192GcmDecr),  gSa2ulMceAes192GcmDecr }
};

/* SA2UL_getMceIndex(), same logic */
static int sa2ul_get_mce_index(const struct Sa2ulAesParams *P, uint8_t *aesKeyInvFlag)
{
    /* per key size: ECB, CBC enc, CBC dec, GCM enc, GCM dec */
    static const int8_t idx[3][5] = {
        { MCE_IDX_AES_128_ECB, MCE_IDX_AES_128_CBC_ENCRYPT, MCE_IDX_AES_128_CBC_DECRYPT,
          MCE_IDX_AES_128_GCM_ENCRYPT, MCE_IDX_AES_128_GCM_DECRYPT },
        { MCE_IDX_AES_192_ECB, MCE_IDX_AES_192_CBC_ENCRYPT, MCE_IDX_AES_192_CBC_DECRYPT,
          MCE_IDX_AES_192_GCM_ENCRYPT, MCE_IDX_AES_192_GCM_DECRYPT },
        { MCE_IDX_AES_256_ECB, MCE_IDX_AES_256_CBC_ENCRYPT, MCE_IDX_AES_256_CBC_DECRYPT,
          MCE_IDX_AES_256_GCM_ENCRYPT, MCE_IDX_AES_256_GCM_DECRYPT },
    };
    const int8_t *k;
    int dec = (P->encDirection == SA2UL_ENC_DIR_DECRYPT);

    *aesKeyInvFlag = 0;
    if (P->encKeySize > SA2UL_ENC_KEYSIZE_256) {
        return -1;
    }
    k = idx[P->encKeySize];

    if (P->encMode == SA2UL_ENC_MODE_ECB) {
        *aesKeyInvFlag = (uint8_t)dec;
        return k[0];
    } else if (P->encMode == SA2UL_ENC_MODE_CBC) {
        *aesKeyInvFlag = (uint8_t)dec;
        return dec ? k[2] : k[1];
    } else if (P->encMode == SA2UL_ENC_MODE_GCM) {
        /* GCM only runs the AES forward direction: no inverse key */
        return dec ? k[4] : k[3];
    }
    return -1;
}

/* AES key expansion
 * SA2UL's hardware needs the *inverse* key schedule preloaded for ECB/CBC
 * decryption (not for GCM -- GCM only ever runs AES forward encryption) */
static const uint32_t gSa2ulAesTe4[256] = {
    0x63636363U, 0x7c7c7c7cU, 0x77777777U, 0x7b7b7b7bU,
    0xf2f2f2f2U, 0x6b6b6b6bU, 0x6f6f6f6fU, 0xc5c5c5c5U,
    0x30303030U, 0x01010101U, 0x67676767U, 0x2b2b2b2bU,
    0xfefefefeU, 0xd7d7d7d7U, 0xababababU, 0x76767676U,
    0xcacacacaU, 0x82828282U, 0xc9c9c9c9U, 0x7d7d7d7dU,
    0xfafafafaU, 0x59595959U, 0x47474747U, 0xf0f0f0f0U,
    0xadadadadU, 0xd4d4d4d4U, 0xa2a2a2a2U, 0xafafafafU,
    0x9c9c9c9cU, 0xa4a4a4a4U, 0x72727272U, 0xc0c0c0c0U,
    0xb7b7b7b7U, 0xfdfdfdfdU, 0x93939393U, 0x26262626U,
    0x36363636U, 0x3f3f3f3fU, 0xf7f7f7f7U, 0xccccccccU,
    0x34343434U, 0xa5a5a5a5U, 0xe5e5e5e5U, 0xf1f1f1f1U,
    0x71717171U, 0xd8d8d8d8U, 0x31313131U, 0x15151515U,
    0x04040404U, 0xc7c7c7c7U, 0x23232323U, 0xc3c3c3c3U,
    0x18181818U, 0x96969696U, 0x05050505U, 0x9a9a9a9aU,
    0x07070707U, 0x12121212U, 0x80808080U, 0xe2e2e2e2U,
    0xebebebebU, 0x27272727U, 0xb2b2b2b2U, 0x75757575U,
    0x09090909U, 0x83838383U, 0x2c2c2c2cU, 0x1a1a1a1aU,
    0x1b1b1b1bU, 0x6e6e6e6eU, 0x5a5a5a5aU, 0xa0a0a0a0U,
    0x52525252U, 0x3b3b3b3bU, 0xd6d6d6d6U, 0xb3b3b3b3U,
    0x29292929U, 0xe3e3e3e3U, 0x2f2f2f2fU, 0x84848484U,
    0x53535353U, 0xd1d1d1d1U, 0x00000000U, 0xededededU,
    0x20202020U, 0xfcfcfcfcU, 0xb1b1b1b1U, 0x5b5b5b5bU,
    0x6a6a6a6aU, 0xcbcbcbcbU, 0xbebebebeU, 0x39393939U,
    0x4a4a4a4aU, 0x4c4c4c4cU, 0x58585858U, 0xcfcfcfcfU,
    0xd0d0d0d0U, 0xefefefefU, 0xaaaaaaaaU, 0xfbfbfbfbU,
    0x43434343U, 0x4d4d4d4dU, 0x33333333U, 0x85858585U,
    0x45454545U, 0xf9f9f9f9U, 0x02020202U, 0x7f7f7f7fU,
    0x50505050U, 0x3c3c3c3cU, 0x9f9f9f9fU, 0xa8a8a8a8U,
    0x51515151U, 0xa3a3a3a3U, 0x40404040U, 0x8f8f8f8fU,
    0x92929292U, 0x9d9d9d9dU, 0x38383838U, 0xf5f5f5f5U,
    0xbcbcbcbcU, 0xb6b6b6b6U, 0xdadadadaU, 0x21212121U,
    0x10101010U, 0xffffffffU, 0xf3f3f3f3U, 0xd2d2d2d2U,
    0xcdcdcdcdU, 0x0c0c0c0cU, 0x13131313U, 0xececececU,
    0x5f5f5f5fU, 0x97979797U, 0x44444444U, 0x17171717U,
    0xc4c4c4c4U, 0xa7a7a7a7U, 0x7e7e7e7eU, 0x3d3d3d3dU,
    0x64646464U, 0x5d5d5d5dU, 0x19191919U, 0x73737373U,
    0x60606060U, 0x81818181U, 0x4f4f4f4fU, 0xdcdcdcdcU,
    0x22222222U, 0x2a2a2a2aU, 0x90909090U, 0x88888888U,
    0x46464646U, 0xeeeeeeeeU, 0xb8b8b8b8U, 0x14141414U,
    0xdedededeU, 0x5e5e5e5eU, 0x0b0b0b0bU, 0xdbdbdbdbU,
    0xe0e0e0e0U, 0x32323232U, 0x3a3a3a3aU, 0x0a0a0a0aU,
    0x49494949U, 0x06060606U, 0x24242424U, 0x5c5c5c5cU,
    0xc2c2c2c2U, 0xd3d3d3d3U, 0xacacacacU, 0x62626262U,
    0x91919191U, 0x95959595U, 0xe4e4e4e4U, 0x79797979U,
    0xe7e7e7e7U, 0xc8c8c8c8U, 0x37373737U, 0x6d6d6d6dU,
    0x8d8d8d8dU, 0xd5d5d5d5U, 0x4e4e4e4eU, 0xa9a9a9a9U,
    0x6c6c6c6cU, 0x56565656U, 0xf4f4f4f4U, 0xeaeaeaeaU,
    0x65656565U, 0x7a7a7a7aU, 0xaeaeaeaeU, 0x08080808U,
    0xbabababaU, 0x78787878U, 0x25252525U, 0x2e2e2e2eU,
    0x1c1c1c1cU, 0xa6a6a6a6U, 0xb4b4b4b4U, 0xc6c6c6c6U,
    0xe8e8e8e8U, 0xddddddddU, 0x74747474U, 0x1f1f1f1fU,
    0x4b4b4b4bU, 0xbdbdbdbdU, 0x8b8b8b8bU, 0x8a8a8a8aU,
    0x70707070U, 0x3e3e3e3eU, 0xb5b5b5b5U, 0x66666666U,
    0x48484848U, 0x03030303U, 0xf6f6f6f6U, 0x0e0e0e0eU,
    0x61616161U, 0x35353535U, 0x57575757U, 0xb9b9b9b9U,
    0x86868686U, 0xc1c1c1c1U, 0x1d1d1d1dU, 0x9e9e9e9eU,
    0xe1e1e1e1U, 0xf8f8f8f8U, 0x98989898U, 0x11111111U,
    0x69696969U, 0xd9d9d9d9U, 0x8e8e8e8eU, 0x94949494U,
    0x9b9b9b9bU, 0x1e1e1e1eU, 0x87878787U, 0xe9e9e9e9U,
    0xcecececeU, 0x55555555U, 0x28282828U, 0xdfdfdfdfU,
    0x8c8c8c8cU, 0xa1a1a1a1U, 0x89898989U, 0x0d0d0d0dU,
    0xbfbfbfbfU, 0xe6e6e6e6U, 0x42424242U, 0x68686868U,
    0x41414141U, 0x99999999U, 0x2d2d2d2dU, 0x0f0f0f0fU,
    0xb0b0b0b0U, 0x54545454U, 0xbbbbbbbbU, 0x16161616U
};

static const uint32_t gSa2ulAesRcon[10] = {
    0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1B000000, 0x36000000
};

static int32_t sa2ul_aes_key_expand_enc(uint32_t *rk, uint32_t *cipherKey, int32_t keyBits)
{
    int32_t i = 0;
    uint32_t temp;
    const uint32_t *Te4 = gSa2ulAesTe4;

    rk[0] = cipherKey[0]; rk[1] = cipherKey[1];
    rk[2] = cipherKey[2]; rk[3] = cipherKey[3];

    if (keyBits == 128) {
        for (;;) {
            temp = rk[3];
            rk[4] = rk[0] ^
                (Te4[(temp >> 16) & 0xff] & 0xff000000) ^
                (Te4[(temp >>  8) & 0xff] & 0x00ff0000) ^
                (Te4[(temp      ) & 0xff] & 0x0000ff00) ^
                (Te4[(temp >> 24)       ] & 0x000000ff) ^
                gSa2ulAesRcon[i];
            rk[5] = rk[1] ^ rk[4];
            rk[6] = rk[2] ^ rk[5];
            rk[7] = rk[3] ^ rk[6];
            if (++i == 10) return 10;
            rk += 4;
        }
    }

    rk[4] = cipherKey[4]; rk[5] = cipherKey[5];

    rk[6] = cipherKey[6]; rk[7] = cipherKey[7];
    if (keyBits == 256) {
        for (;;) {
            temp = rk[7];
            rk[8] = rk[0] ^
                (Te4[(temp >> 16) & 0xff] & 0xff000000) ^
                (Te4[(temp >>  8) & 0xff] & 0x00ff0000) ^
                (Te4[(temp      ) & 0xff] & 0x0000ff00) ^
                (Te4[(temp >> 24)       ] & 0x000000ff) ^
                gSa2ulAesRcon[i];
            rk[9]  = rk[1] ^ rk[8];
            rk[10] = rk[2] ^ rk[9];
            rk[11] = rk[3] ^ rk[10];
            if (++i == 7) return 14;
            temp = rk[11];
            rk[12] = rk[4] ^
                (Te4[(temp >> 24)       ] & 0xff000000) ^
                (Te4[(temp >> 16) & 0xff] & 0x00ff0000) ^
                (Te4[(temp >>  8) & 0xff] & 0x0000ff00) ^
                (Te4[(temp      ) & 0xff] & 0x000000ff);
            rk[13] = rk[5] ^ rk[12];
            rk[14] = rk[6] ^ rk[13];
            rk[15] = rk[7] ^ rk[14];
            rk += 8;
        }
    }
    return 0;
}

static void sa2ul_aes_inv_key(uint32_t *invKey, uint32_t *cipherKey, int32_t keyBits)
{
    uint32_t roundKey[60];
    uint32_t *rk = &roundKey[0];
    uint32_t *pInvRK = &roundKey[40];
    int32_t keySize = keyBits >> 5;

    if (keyBits == 128) {
        sa2ul_aes_key_expand_enc(rk, cipherKey, 128);
    }
    if (keyBits == 192) {
        const uint32_t *Te4 = gSa2ulAesTe4;
        uint32_t temp;
        int32_t i = 0;

        rk[0] = cipherKey[0]; rk[1] = cipherKey[1];
        rk[2] = cipherKey[2]; rk[3] = cipherKey[3];
        rk[4] = cipherKey[4]; rk[5] = cipherKey[5];
        for (;;) {
            temp = rk[5];
            rk[6] = rk[0] ^
                (Te4[(temp >> 16) & 0xff] & 0xff000000) ^
                (Te4[(temp >>  8) & 0xff] & 0x00ff0000) ^
                (Te4[(temp      ) & 0xff] & 0x0000ff00) ^
                (Te4[(temp >> 24)       ] & 0x000000ff) ^
                gSa2ulAesRcon[i];
            rk[7]  = rk[1] ^ rk[6];
            rk[8]  = rk[2] ^ rk[7];
            rk[9]  = rk[3] ^ rk[8];
            rk[10] = rk[4] ^ rk[9];
            rk[11] = rk[5] ^ rk[10];
            if (++i == 8) {
                break;
            }
            rk += 6;
        }
        pInvRK = &roundKey[48];
    }
    if (keyBits == 256) {
        sa2ul_aes_key_expand_enc(rk, cipherKey, 256);
        pInvRK = &roundKey[52];
    }
    memcpy(invKey, pInvRK, (size_t)keySize * 4u);
}

static void sa2ul_u8_le_to_u32(uint32_t *dest, const uint8_t *src, uint32_t len)
{
    uint32_t i, t = 0;
    for (i = 0; i < len; i++) {
        t = (t << 8) | src[i];
        if ((i & 3) == 3) { *dest++ = t; t = 0; }
    }
    if ((i & 3) != 0) { *dest = t << ((4 - (i & 3)) << 3); }
}

static void sa2ul_u32_le_to_u8(uint8_t *dest, const uint32_t *src, uint32_t len)
{
    uint32_t i, t;
    for (i = 0; i < len; i += 4) {
        t = *src++;
        *dest++ = (uint8_t)(t >> 24); *dest++ = (uint8_t)(t >> 16);
        *dest++ = (uint8_t)(t >> 8);  *dest++ = (uint8_t)t;
    }
}

static void sa2ul_64b_endian_swap(uint32_t *dest, const uint32_t *src, uint32_t len)
{
    uint32_t tmp[4], *t;
    uint32_t i, j;
    for (i = 0; i < len; i += 16) {
        t = &tmp[0];
        for (j = 0; j < 4; j++) *t++ = *src++;
        for (j = 0; j < 4; j++) *dest++ = *--t;
    }
}

/* DMA/ring plumbing
 *
 * AM64x SA2UL sits behind the DMSS PKTDMA
 *
 *   - mapped channels are fixed per PSI-L thread (CSL_DMSS_PKTDMA_*_SAUL*),
 *   - TX ring number == tflow ID, RX ring number == TFlowCount + rflow ID,
 *   - each ring is a dual (forward + reverse) ring on one ring memory,
 *   - the BSP's J7RingAcc_CreateRingMemIODev() does NOT configure the ring
 *     through TISCI, so J7Sci_ConfigureRingAccelerator() is called here,
 *   - PSI-L threads are paired, then the channel RT registers are enabled.
 *
 * SA2UL's egress picks rx thread 0x4002 or 0x4003 by packet size, so
 * both rx channels are bound to one rflow, and therefore one ring.
 */

struct Sa2ulPsilMap {
    Value thread;
    Value chan;
    Value chanSubtype;
    Value flowSubtype;
};

static const struct Sa2ulPsilMap gSa2ulTxMap[] = {
    { 0xc000u, 24u, 2u, 2u },   /* SAUL_TX_0 */
    { 0xc001u, 25u, 3u, 3u },   /* SAUL_TX_1 */
};
static const struct Sa2ulPsilMap gSa2ulRxMap[] = {
    { 0x4000u, 17u, 2u, 2u },   /* SAUL_RX_0, FLOW_SAUL_RX_0/1 */
    { 0x4001u, 18u, 3u, 2u },   /* SAUL_RX_1, FLOW_SAUL_RX_0/1 */
    { 0x4002u, 19u, 4u, 3u },   /* SAUL_RX_2, FLOW_SAUL_RX_2/3 */
    { 0x4003u, 20u, 5u, 3u },   /* SAUL_RX_3, FLOW_SAUL_RX_2/3 */
};

static const struct Sa2ulPsilMap *sa2ul_psil_lookup(
        const struct Sa2ulPsilMap *map, size_t n, Value thread)
{
    size_t i;
    /* The DT tx thread carries the PSI-L destination bit (0x8000) */
    thread |= (map == gSa2ulTxMap) ? SA2UL_PSIL_DST_THREAD_OFFSET : 0u;
    for (i = 0; i < n; i++) {
        if (map[i].thread == thread) {
            return &map[i];
        }
    }
    return NULL;
}

#define SA2UL_RING_ELEMS      8u
#define SA2UL_DMA_ALIGN       128u      /* >= A53 cache line; TI documents the
                                         * security context as 128B aligned */
#define SA2UL_DESC_SIZE       128u      /* CPPI5 host desc + EPIB + PS words,
                                         * rounded up to SA2UL_DMA_ALIGN */
#define SA2UL_CONTEXT_ID_START   0x80u  /* TI SA2UL_Attrs.contextIdStart */
#define SA2UL_CONTEXT_ID_MAX_NUM 16u    /* TI SA2UL_Attrs.contextIdMaxNum */

#ifndef SA2UL_SCCTL2_PRIVID_VAL
    #define SA2UL_SCCTL2_PRIVID_VAL 0xc3u
#endif
#ifndef SA2UL_SCCTL2_PRIV_VAL
    #define SA2UL_SCCTL2_PRIV_VAL   0u
#endif
#ifndef SA2UL_SCCTL2_SECURE_VAL
    #define SA2UL_SCCTL2_SECURE_VAL 0u
#endif

/* Polling budget for a single SA2UL operation. Iteration based (no time
 * base in this context); tune during bring-up or move to INTA interrupts. */
#ifndef SA2UL_POLL_LIMIT
    #define SA2UL_POLL_LIMIT 10000000u
#endif

/* Everything SA2UL's DMA engine reads or writes. Allocated with
 * MemorySpace_AllocateDmaMemory(), so its physical address is known. */
struct Sa2ulPool {
    uint64_t txRingMem[SA2UL_RING_ELEMS] __attribute__((aligned(SA2UL_DMA_ALIGN)));
    uint64_t rxRingMem[SA2UL_RING_ELEMS] __attribute__((aligned(SA2UL_DMA_ALIGN)));
    union {
        struct Sa2ulHostDescrTx d;
        uint8_t pad[SA2UL_DESC_SIZE];
    } tx __attribute__((aligned(SA2UL_DMA_ALIGN)));
    union {
        struct Sa2ulHostDescrRx d;
        uint8_t pad[SA2UL_DESC_SIZE];
    } rx __attribute__((aligned(SA2UL_DMA_ALIGN)));
    struct Sa2ulContext ctx __attribute__((aligned(SA2UL_DMA_ALIGN)));
    /* bounce buffer: data is copied here from the Task-shared page, so the
     * shared page itself never needs a known physical address */
    uint8_t buf[SA2UL_MAX_BUF] __attribute__((aligned(SA2UL_DMA_ALIGN)));
};

static struct Sa2ulPool *gPool = NULL;   /* kernel VA */
static uint64_t gPoolPhys = 0;
static int gSa2ulReady = 0;

/* A DMA operation failed in a way that leaves descriptors owned by the
 * hardware (push failure, timeout, wrong descriptor returned): stop using
 * the engine; callers fall back to software. */
static void sa2ul_dma_broken(void)
{
    gSa2ulReady = 0;
}
static uint8_t gNextCtxId = 0;

static J7DmaDev *gDmaDev = NULL;
static Value gTxRingId, gRxRingId, gRxFlowId;
static J7RingDev gTxRing, gTxCqRing, gRxRing, gRxCqRing;
static J7DmaChannelDev gTxChanDev, gRx1ChanDev, gRx2ChanDev;

static uint64_t sa2ul_phys(const volatile void *p)
{
    return gPoolPhys + (uint64_t)((uintptr_t)p - (uintptr_t)gPool);
}

static void sa2ul_dma_flush(const volatile void *p, size_t len)
{
    (void)ASP_FlushCaches((Address)(uintptr_t)p, (Address)len);
}

static void sa2ul_dma_invalidate(const volatile void *p, size_t len)
{
    (void)ASP_InvalidateCaches((Address)(uintptr_t)p, (Address)len);
}

/* SMP-safe lock around the single descriptor pair / bounce buffer. */
static volatile unsigned int gSa2ulLock = 0u;

static void sa2ul_lock(void)
{
    for (;;) {
        if (__LDXR32((unsigned int *)&gSa2ulLock) == 0u) {
            if (__STXR32(1u, (unsigned int *)&gSa2ulLock) == 0) {
                break;
            }
        }
    }
    __DMB();
}

static void sa2ul_unlock(void)
{
    __DMB();
    gSa2ulLock = 0u;
}

/* One dual ring: reverse (completion) + forward (submit) on the same
 * ring memory, configured through TISCI. */
static Error sa2ul_create_ring(Value RingId, uint64_t *RingMem, Value Asel,
        const char *FwdName, const char *RvsName, Value DevNo,
        J7RingDev *Fwd, J7RingDev *Rvs)
{
    Error err;
    J7RingAccDev *acc = gDmaDev->RingAcc;

    err = J7RingAcc_CreateRingMemIODev(acc, RingId, sizeof(uint64_t),
            SA2UL_RING_ELEMS, (Address)(uintptr_t)RingMem, DevNo, RvsName,
            (Address)0, Rvs, true);
    if (err == Success) {
        err = J7Sci_ConfigureRingAccelerator(acc->SciDev, acc->SciDevId,
                RingId, (Address)sa2ul_phys(RingMem), SA2UL_RING_ELEMS,
                sizeof(uint64_t), true, Asel);
    }
    if (err == Success) {
        err = J7RingAcc_CreateRingMemIODev(acc, RingId, sizeof(uint64_t),
                SA2UL_RING_ELEMS, (Address)(uintptr_t)RingMem, DevNo, FwdName,
                (Address)0, Fwd, false);
    }
    return err;
}

static void sa2ul_chan_enable(J7DmaChannelDev *Chan, Boolean IsTx)
{
    Value en = FieldValue(UDMA_CHANRT_CTL_EN, 1);

    if (IsTx) {
        IOReg_Write(Chan->Ioa, UDMA_CHANRT_PEER_RT_EN, en);
        IOReg_SetField(Chan->Ioa, UDMA_CHANRT_CTL, UDMA_CHANRT_CTL_EN, 1);
    }
    else {
        IOReg_SetField(Chan->Ioa, UDMA_CHANRT_CTL, UDMA_CHANRT_CTL_EN, 1);
        IOReg_Write(Chan->Ioa, UDMA_CHANRT_PEER_RT_EN, en);
    }
}

#define SA2UL_CHECK(expr, what) do { \
        Error e_ = (expr); \
        if (e_ != Success) { \
            SA2UL_LOG("sa2ul_driver_init: %s failed (err=%d)\n", what, (int)e_); \
            return -1; \
        } \
    } while (0)

int sa2ul_driver_init(volatile void *CpAceBase, J7DmaDev *DmaDev,
        Value TxThread, Value Rx1Thread, Value Rx2Thread, Value Asel)
{
    const struct Sa2ulPsilMap *tx, *rx1, *rx2;
    MemorySpaceAddress poolPhys = 0;
    Address poolKern = 0;
    Value tflow;

    SA2UL_TRACE("engine check");
    gCpAceBase = (volatile uint8_t *)CpAceBase;
    if (sa2ul_engine_enable() != 0) {
        return -1;
    }

    if (DmaDev == NULL || DmaDev->DmaType != DMA_TYPE_PKTDMA ||
            DmaDev->RingAcc == NULL) {
        SA2UL_LOG("sa2ul_driver_init: crypto node's DMA is not an initialized "
               "PKTDMA\n");
        return -1;
    }
    gDmaDev = DmaDev;

    tx  = sa2ul_psil_lookup(gSa2ulTxMap, DIM(gSa2ulTxMap), TxThread);
    rx1 = sa2ul_psil_lookup(gSa2ulRxMap, DIM(gSa2ulRxMap), Rx1Thread);
    rx2 = sa2ul_psil_lookup(gSa2ulRxMap, DIM(gSa2ulRxMap), Rx2Thread);
    if (tx == NULL || rx1 == NULL || rx2 == NULL ||
            rx1->flowSubtype != rx2->flowSubtype) {
        SA2UL_LOG("sa2ul_driver_init: unexpected PSI-L threads tx=0x%lx "
               "rx1=0x%lx rx2=0x%lx\n", (unsigned long)TxThread,
               (unsigned long)Rx1Thread, (unsigned long)Rx2Thread);
        return -1;
    }

    SA2UL_TRACE("allocate DMA pool");
    /* DMA-able memory for rings, descriptors, context and bounce buffer */
    SA2UL_CHECK(MemorySpace_AllocateDmaMemory(&PhysicalMemorySpace,
            ROUNDUP(sizeof(struct Sa2ulPool), ASP_PAGESIZE), ASP_PAGESIZE,
            MEMORY_RW, HardwareCacheCoherency, NULL, &poolPhys, &poolKern,
            NULL), "MemorySpace_AllocateDmaMemory");
    gPool = (struct Sa2ulPool *)poolKern;
    gPoolPhys = (uint64_t)poolPhys;
    memset(gPool, 0, sizeof(*gPool));
    sa2ul_dma_flush(gPool, sizeof(*gPool));

    SA2UL_TRACE("allocate flows");
    /* TX: ring == tflow */
    SA2UL_CHECK(J7Dma_AllocTFlowIDRange(gDmaDev, tx->flowSubtype, &tflow, 1),
            "J7Dma_AllocTFlowIDRange");
    gTxRingId = tflow;

    /* RX: one rflow (and ring) shared by both rx threads */
    SA2UL_CHECK(J7Dma_AllocRFlowIDRange(gDmaDev, rx1->flowSubtype,
            &gRxFlowId, 1), "J7Dma_AllocRFlowIDRange");
    gRxRingId = gDmaDev->TFlowCount + gRxFlowId;

    SA2UL_LOG("sa2ul_driver_init: tx chan %lu ring %lu, rx chans %lu/%lu "
           "flow %lu ring %lu, pool phys 0x%lx\n",
           (unsigned long)tx->chan, (unsigned long)gTxRingId,
           (unsigned long)rx1->chan, (unsigned long)rx2->chan,
           (unsigned long)gRxFlowId, (unsigned long)gRxRingId,
           (unsigned long)gPoolPhys);

    SA2UL_TRACE("configure tx channel");
    SA2UL_CHECK(J7Dma_ConfigureTxChannel(gDmaDev, tx->chan, gTxRingId,
            SA2UL_DESC_SIZE), "J7Dma_ConfigureTxChannel");
    SA2UL_TRACE("create tx ring");
    SA2UL_CHECK(sa2ul_create_ring(gTxRingId, gPool->txRingMem, Asel,
            "Sa2ulTxRingDev%d", "Sa2ulTxCqRingDev%d", 0, &gTxRing, &gTxCqRing),
            "tx ring");

    SA2UL_TRACE("configure rx channels");
    SA2UL_CHECK(J7Dma_ConfigureRxChannel(gDmaDev, rx1->chan, gRxFlowId, 1,
            gRxRingId, gRxRingId, SA2UL_DESC_SIZE), "J7Dma_ConfigureRxChannel rx1");
    SA2UL_CHECK(J7Dma_ConfigureRxChannel(gDmaDev, rx2->chan, gRxFlowId, 1,
            gRxRingId, gRxRingId, SA2UL_DESC_SIZE), "J7Dma_ConfigureRxChannel rx2");
    SA2UL_TRACE("create rx ring");
    SA2UL_CHECK(sa2ul_create_ring(gRxRingId, gPool->rxRingMem, Asel,
            "Sa2ulRxRingDev%d", "Sa2ulRxCqRingDev%d", 0, &gRxRing, &gRxCqRing),
            "rx ring");

    SA2UL_TRACE("PSI-L pairing");
    SA2UL_CHECK(J7Dma_ConfigurePSILPair(gDmaDev, gDmaDev->PSILBase + tx->chan,
            tx->thread), "PSI-L pair tx");
    SA2UL_CHECK(J7Dma_ConfigurePSILPair(gDmaDev, rx1->thread,
            gDmaDev->PSILBase + rx1->chan), "PSI-L pair rx1");
    SA2UL_CHECK(J7Dma_ConfigurePSILPair(gDmaDev, rx2->thread,
            gDmaDev->PSILBase + rx2->chan), "PSI-L pair rx2");

    SA2UL_TRACE("channel RT iodevs");
    SA2UL_CHECK(J7Dma_CreateChannelIODev(gDmaDev, true, tx->chan, tx->chan,
            "Sa2ulTxDmaDev%d", &gTxChanDev), "tx channel iodev");
    SA2UL_CHECK(J7Dma_CreateChannelIODev(gDmaDev, false, rx1->chan, rx1->chan,
            "Sa2ulRxDmaDev%d", &gRx1ChanDev), "rx1 channel iodev");
    SA2UL_CHECK(J7Dma_CreateChannelIODev(gDmaDev, false, rx2->chan, rx2->chan,
            "Sa2ulRxDmaDev%d", &gRx2ChanDev), "rx2 channel iodev");

    SA2UL_TRACE("enable rx channels");
    sa2ul_chan_enable(&gRx1ChanDev, false);
    sa2ul_chan_enable(&gRx2ChanDev, false);
    SA2UL_TRACE("enable tx channel");
    sa2ul_chan_enable(&gTxChanDev, true);

    gSa2ulReady = 1;
    SA2UL_TRACE("init done");
    return 0;
}

static uint8_t sa2ul_next_ctx_id(void)
{
    uint8_t id = (uint8_t)(SA2UL_CONTEXT_ID_START + gNextCtxId);
    gNextCtxId = (uint8_t)((gNextCtxId + 1u) % SA2UL_CONTEXT_ID_MAX_NUM);
    return id;
}

static uint32_t sa2ul_scctl2(void)
{
    return FLD(SA2UL_SCCTL2_PRIVID_VAL, SA2UL_SCCTL2_PRIVID_SHIFT, SA2UL_SCCTL2_PRIVID_MASK) |
           FLD(SA2UL_SCCTL2_PRIV_VAL, SA2UL_SCCTL2_PRIV_SHIFT, SA2UL_SCCTL2_PRIV_MASK) |
           FLD(SA2UL_SCCTL2_SECURE_VAL, SA2UL_SCCTL2_SECURE_SHIFT, SA2UL_SCCTL2_SECURE_MASK);
}

/* just for aes */
static int sa2ul_context_alloc(volatile struct Sa2ulContext *ctxObj,
        const struct Sa2ulAesParams *ctxPrms)
{
    struct Sa2ulSecCtx sc;
    int32_t mcDataIndex;
    uint8_t aesKeyInvFlag;
    uint64_t authLen, aadLen;

    memset((void *)&sc, 0, sizeof(sc));
    memcpy((void *)&ctxObj->prms, ctxPrms, sizeof(*ctxPrms));
    ctxObj->totalLengthInBytes = ctxPrms->inputLen;
    ctxObj->opType = SA2UL_OP_ENC;
    ctxObj->secCtxId = sa2ul_next_ctx_id();

    authLen = ((uint64_t)ctxPrms->inputLen) << 3;

    mcDataIndex = sa2ul_get_mce_index(ctxPrms, &aesKeyInvFlag);
    if (mcDataIndex < 0) {
        return -1;
    }

    sc.u.enc.encrCtl =
        FLD(0u, SA2UL_ENCRCTL_MODESEL_SHIFT, SA2UL_ENCRCTL_MODESEL_MASK) |
        FLD(0u, SA2UL_ENCRCTL_USE_DKEK_SHIFT, SA2UL_ENCRCTL_USE_DKEK_MASK) |
        FLD(SA2UL_ENGINE_CODE_DEFAULT_EGRESS_PORT, SA2UL_ENCRCTL_DEFAULT_NEXT_ENGINE_ID_SHIFT, SA2UL_ENCRCTL_DEFAULT_NEXT_ENGINE_ID_MASK) |
        FLD(0u, SA2UL_ENCRCTL_TRAILER_EVERY_CHUNK_SHIFT, SA2UL_ENCRCTL_TRAILER_EVERY_CHUNK_MASK) |
        FLD(0u, SA2UL_ENCRCTL_TRAILER_AT_END_SHIFT, SA2UL_ENCRCTL_TRAILER_AT_END_MASK) |
        FLD(1u, SA2UL_ENCRCTL_PKT_DATA_SECTION_UPDATE_SHIFT, SA2UL_ENCRCTL_PKT_DATA_SECTION_UPDATE_MASK) |
        FLD(0u, SA2UL_ENCRCTL_ENCRYPT_DECRYPT_SHIFT, SA2UL_ENCRCTL_ENCRYPT_DECRYPT_MASK) |
        FLD(SA2UL_EncBlksizeEncoded[SA2UL_ENC_ALG_AES], SA2UL_ENCRCTL_BLK_SIZE_SHIFT, SA2UL_ENCRCTL_BLK_SIZE_MASK) |
        FLD(gSa2ulMceDataArray[mcDataIndex].sopOffset, SA2UL_ENCRCTL_SOP_OFFSET_SHIFT, SA2UL_ENCRCTL_SOP_OFFSET_MASK) |
        FLD(gSa2ulMceDataArray[mcDataIndex].middleOffset, SA2UL_ENCRCTL_MIDDLE_OFFSET_SHIFT, SA2UL_ENCRCTL_MIDDLE_OFFSET_MASK) |
        FLD(gSa2ulMceDataArray[mcDataIndex].eopOffset, SA2UL_ENCRCTL_EOP_OFFSET_SHIFT, SA2UL_ENCRCTL_EOP_OFFSET_MASK);

    if (ctxPrms->encMode == SA2UL_ENC_MODE_GCM) {
        sc.u.enc.encrCtl |= FLD(1u, SA2UL_ENCRCTL_TRAILER_AT_END_SHIFT, SA2UL_ENCRCTL_TRAILER_AT_END_MASK);
    } else {
        sc.u.enc.encrCtl |= FLD(ctxPrms->encDirection, SA2UL_ENCRCTL_ENCRYPT_DECRYPT_SHIFT, SA2UL_ENCRCTL_ENCRYPT_DECRYPT_MASK);
    }

    sa2ul_u8_le_to_u32(sc.u.enc.modeCtrlInstrs, gSa2ulMceDataArray[mcDataIndex].mcInstrs,
            gSa2ulMceDataArray[mcDataIndex].nMCInstrs);
    sc.u.enc.hwCtrlWord = 0;

    sa2ul_u8_le_to_u32(sc.u.enc.encKeyValue, ctxPrms->key, SA2UL_MAX_KEY_SIZE_BYTES);
    if (aesKeyInvFlag) {
        sa2ul_aes_inv_key(sc.u.enc.encKeyValue, sc.u.enc.encKeyValue,
                SA2UL_ENC_KEYSIZE_BITS(ctxPrms->encKeySize));
    }

    if (ctxPrms->encMode == SA2UL_ENC_MODE_GCM) {
        sa2ul_u8_le_to_u32(sc.u.enc.encAux3, ctxPrms->iv, SA2UL_MAX_IV_SIZE_BYTES_GCM);
        sc.u.enc.encAux3[SA2UL_MAX_IV_SIZE_BYTES_GCM / 4u] = 0x1u;
        sa2ul_u8_le_to_u32(sc.u.enc.encAux1, ctxPrms->ghash, SA2UL_GHASH_LENGTH_BYTES);
        sa2ul_u8_le_to_u32(sc.u.enc.encAux2, ctxPrms->aad, SA2UL_MAX_AAD_SIZE_BYTES);
        aadLen = ((uint64_t)ctxPrms->aadLen) << 3;
        sc.u.enc.encAux1[4] = (uint32_t)(aadLen >> 32);
        /* low word: the SDK masks this with 0xFFFF, which truncates any
         * length >= 8 KiB in bits; harmless at SA2UL_MAX_BUF but wrong */
        sc.u.enc.encAux1[5] = (uint32_t)aadLen;
        sc.u.enc.encAux1[6] = (uint32_t)(authLen >> 32);
        sc.u.enc.encAux1[7] = (uint32_t)authLen;
    } else {
        /* encAux2, not the SDK's encAux3 -- per wolfBoot's
         * mcuplussdk_11.02.00_sa2ul.c.patch */
        sa2ul_u8_le_to_u32(sc.u.enc.encAux2, ctxPrms->iv, SA2UL_MAX_IV_SIZE_BYTES);
    }

    sc.scctl.scctl1 =
        FLD(1u, SA2UL_SCCTL1_OWNER_SHIFT, SA2UL_SCCTL1_OWNER_MASK) |
        FLD(1u, SA2UL_SCCTL1_EVICT_DONE_SHIFT, SA2UL_SCCTL1_EVICT_DONE_MASK) |
        FLD(0x8Du, SA2UL_SCCTL1_FETCH_EVICT_CONTROL_SHIFT, SA2UL_SCCTL1_FETCH_EVICT_CONTROL_MASK);

    sc.scctl.scctl2 = sa2ul_scctl2();

    sa2ul_64b_endian_swap((uint32_t *)&ctxObj->secCtx, (uint32_t *)&sc, sizeof(sc));

    /* TI's CacheP_wb()+CacheP_inv() pair */
    sa2ul_dma_flush(&ctxObj->secCtx, sizeof(ctxObj->secCtx));

    return 0;
}

/* just for sha */
static int sa2ul_context_alloc_auth(volatile struct Sa2ulContext *ctxObj,
        uint8_t hashAlg, uint32_t inputLen)
{
    struct Sa2ulSecCtx sc;
    uint64_t authLen;

    memset((void *)&sc, 0, sizeof(sc));
    ctxObj->totalLengthInBytes = inputLen;
    ctxObj->opType = SA2UL_OP_AUTH;
    ctxObj->secCtxId = sa2ul_next_ctx_id();
    ctxObj->hashAlg = hashAlg;

    authLen = ((uint64_t)inputLen) << 3;

    sc.u.auth.authCtx1 =
        FLD(0u, SA2UL_AUTHCTX1_MODESEL_SHIFT, SA2UL_AUTHCTX1_MODESEL_MASK) |
        FLD(SA2UL_ENGINE_CODE_DEFAULT_EGRESS_PORT, SA2UL_AUTHCTX1_DEFAULT_NEXT_ENGINE_ID_SHIFT, SA2UL_AUTHCTX1_DEFAULT_NEXT_ENGINE_ID_MASK) |
        FLD(0x40u | hashAlg, SA2UL_AUTHCTX1_SW_CONTROL_SHIFT, SA2UL_AUTHCTX1_SW_CONTROL_MASK);

    sc.u.auth.authenticationLengthLo = (uint32_t)authLen;
    sc.u.auth.authenticationLengthHi = (uint32_t)(authLen >> 32);

    /* FETCH_EVICT_CONTROL is 0x91 here, vs the aes path's 0x8D above */
    sc.scctl.scctl1 =
        FLD(1u, SA2UL_SCCTL1_OWNER_SHIFT, SA2UL_SCCTL1_OWNER_MASK) |
        FLD(1u, SA2UL_SCCTL1_EVICT_DONE_SHIFT, SA2UL_SCCTL1_EVICT_DONE_MASK) |
        FLD(0x91u, SA2UL_SCCTL1_FETCH_EVICT_CONTROL_SHIFT, SA2UL_SCCTL1_FETCH_EVICT_CONTROL_MASK);

    sc.scctl.scctl2 = sa2ul_scctl2();

    sa2ul_64b_endian_swap((uint32_t *)&ctxObj->secCtx, (uint32_t *)&sc, sizeof(sc));

    sa2ul_dma_flush(&ctxObj->secCtx, sizeof(ctxObj->secCtx));

    return 0;
}

/* Push + poll-pop, combined into one synchronous call.
 * Caller holds sa2ul_lock(). TrailerOut receives the hash / GCM tag. */
#define SA2UL_DESC_ADDR_MASK 0x0000ffffffffffffull  /* strip ASEL [51:48] */

static int sa2ul_context_process(volatile struct Sa2ulContext *ctxObj,
        uint32_t ilen, uint8_t TrailerOut[SA2UL_MAX_HASH_SIZE_BYTES])
{
    struct Sa2ulHostDescrTx *txDescr = &gPool->tx.d;
    struct Sa2ulHostDescrRx *rxDescr = &gPool->rx.d;
    uint64_t bufPhys = sa2ul_phys(gPool->buf);
    uint64_t txPhys = sa2ul_phys(txDescr);
    uint64_t rxPhys = sa2ul_phys(rxDescr);
    uint32_t engineId = (ctxObj->opType == SA2UL_OP_AUTH) ?
            SA2UL_ENGINE_CODE_AUTHENTICATION_MODULE_P1 :
            SA2UL_ENGINE_CODE_ENCRYPTION_MODULE_P1;
    uint32_t trailerBytes = (ctxObj->opType == SA2UL_OP_AUTH) ?
            gSa2ulHashSizeBytes[ctxObj->hashAlg & 7u] :
            ((ctxObj->prms.encMode == SA2UL_ENC_MODE_GCM) ?
                    SA2UL_AES_GCM_AUTHTAG_SIZE_IN_BYTES : 0u);
    uint64_t phys;
    uint32_t reg, waited;
    int gotRx = 0, gotTx = 0;

    memset(txDescr, 0, sizeof(*txDescr));
    txDescr->pd.descInfo =
        FLD(CPPI5_PD_DESCINFO_DTYPE_VAL_HOST, UDMAP_CPPI5_PD_DESCINFO_DTYPE_SHIFT, UDMAP_CPPI5_PD_DESCINFO_DTYPE_MASK) |
        FLD(CPPI5_PD_DESCINFO_EINFO_VAL_IS_PRESENT, UDMAP_CPPI5_PD_DESCINFO_EINFO_SHIFT, UDMAP_CPPI5_PD_DESCINFO_EINFO_MASK) |
        FLD(12u >> 2, UDMAP_CPPI5_PD_DESCINFO_PSWCNT_SHIFT, UDMAP_CPPI5_PD_DESCINFO_PSWCNT_MASK) |
        FLD(ilen, UDMAP_CPPI5_PD_DESCINFO_PKTLEN_SHIFT, UDMAP_CPPI5_PD_DESCINFO_PKTLEN_MASK);
    /* egress flow, as TI sets object->udmapRxFlownum */
    txDescr->pd.pktInfo1 =
        FLD((uint32_t)gRxFlowId, UDMAP_CPPI5_PD_PKTINFO1_FLOWID_SHIFT, UDMAP_CPPI5_PD_PKTINFO1_FLOWID_MASK);
    txDescr->pd.pktInfo2 =
        FLD((uint32_t)gTxRingId, UDMAP_CPPI5_PD_PKTINFO2_RETQ_SHIFT, UDMAP_CPPI5_PD_PKTINFO2_RETQ_MASK);
    /* Single-shot: every op is the last packet, so always evict and tear
     * down the context (TI does this on the final chunk) */
    txDescr->exPktInfo.swWord0 =
        FLD(1u, SA2UL_SWWORD0_CPPI_DST_INFO_PRESENT_SHIFT, SA2UL_SWWORD0_CPPI_DST_INFO_PRESENT_MASK) |
        FLD(1u, SA2UL_SWWORD0_CMD_LBL_PRESENT_SHIFT, SA2UL_SWWORD0_CMD_LBL_PRESENT_MASK) |
        FLD(0u, SA2UL_SWWORD0_CMD_LBL_OFFSET_SHIFT, SA2UL_SWWORD0_CMD_LBL_OFFSET_MASK) |
        FLD(ctxObj->secCtxId, SA2UL_SWWORD0_SCID_SHIFT, SA2UL_SWWORD0_SCID_MASK) |
        FLD(engineId, SA2UL_SWWORD0_ENGINE_ID_SHIFT, SA2UL_SWWORD0_ENGINE_ID_MASK) |
        FLD(1u, SA2UL_SWWORD0_TEARDOWN_SHIFT, SA2UL_SWWORD0_TEARDOWN_MASK) |
        FLD(1u, SA2UL_SWWORD0_EVICT_SHIFT, SA2UL_SWWORD0_EVICT_MASK);
    txDescr->psData.cmdLblHdr1 =
        FLD(ilen, SA2UL_CMDLBLHDR1_LEN_TO_BE_PROCESSESED_SHIFT, SA2UL_CMDLBLHDR1_LEN_TO_BE_PROCESSESED_MASK) |
        FLD(8u, SA2UL_CMDLBLHDR1_CMD_LABEL_LEN_SHIFT, SA2UL_CMDLBLHDR1_CMD_LABEL_LEN_MASK) |
        FLD(SA2UL_ENGINE_CODE_DEFAULT_EGRESS_PORT, SA2UL_CMDLBLHDR1_NEXT_ENGINE_SELECT_CODE_SHIFT, SA2UL_CMDLBLHDR1_NEXT_ENGINE_SELECT_CODE_MASK);

    if (ctxObj->opType == SA2UL_OP_AUTH &&
            ctxObj->totalLengthInBytes > SA2UL_CMDLBLHDR1_LEN_TO_BE_PROCESSESED_MASK) {
        uint64_t authLen = ((uint64_t)ctxObj->totalLengthInBytes) << 3;

        txDescr->pd.descInfo &= ~UDMAP_CPPI5_PD_DESCINFO_PSWCNT_MASK;
        txDescr->pd.descInfo |= FLD(20u >> 2,
                UDMAP_CPPI5_PD_DESCINFO_PSWCNT_SHIFT, UDMAP_CPPI5_PD_DESCINFO_PSWCNT_MASK);
        txDescr->psData.cmdLblHdr1 &= ~SA2UL_CMDLBLHDR1_CMD_LABEL_LEN_MASK;
        txDescr->psData.cmdLblHdr1 |= FLD(16u,
                SA2UL_CMDLBLHDR1_CMD_LABEL_LEN_SHIFT, SA2UL_CMDLBLHDR1_CMD_LABEL_LEN_MASK);
        txDescr->psData.cmdLblHdr2 =
            FLD(1u, SA2UL_CMDLBLHDR2_OPTION1_CTX_OFFSET_SHIFT, SA2UL_CMDLBLHDR2_OPTION1_CTX_OFFSET_MASK) |
            FLD(1u, SA2UL_CMDLBLHDR2_OPTION1_LEN_SHIFT, SA2UL_CMDLBLHDR2_OPTION1_LEN_MASK);
        txDescr->psData.optionWords[0] = (uint32_t)(authLen >> 32);
        txDescr->psData.optionWords[1] = (uint32_t)authLen;
    }

    phys = sa2ul_phys(&ctxObj->secCtx);
    txDescr->exPktInfo.scptrL = (uint32_t)phys;
    txDescr->exPktInfo.scptrH = (uint32_t)(phys >> 32);
    if (trailerBytes != 0u) {
        txDescr->exPktInfo.scptrH |= FLD(trailerBytes,
                SA2UL_SCPTRH_EGRESS_CPPI_STATUS_LEN_SHIFT, SA2UL_SCPTRH_EGRESS_CPPI_STATUS_LEN_MASK);
    }
    txDescr->psData.inPsiInfo = FLD((uint32_t)gRxRingId,
            SA2UL_INPSIINFO_EGRESS_CPPI_DEST_QUEUE_NUM_SHIFT, SA2UL_INPSIINFO_EGRESS_CPPI_DEST_QUEUE_NUM_MASK);

    txDescr->pd.bufPtr = bufPhys;    txDescr->pd.bufInfo1 = ilen;
    txDescr->pd.orgBufPtr = bufPhys; txDescr->pd.orgBufLen = ilen;

    memset(rxDescr, 0, sizeof(*rxDescr));
    rxDescr->pd.descInfo = FLD(CPPI5_PD_DESCINFO_DTYPE_VAL_HOST,
            UDMAP_CPPI5_PD_DESCINFO_DTYPE_SHIFT, UDMAP_CPPI5_PD_DESCINFO_DTYPE_MASK);
    rxDescr->pd.bufPtr = bufPhys;    rxDescr->pd.bufInfo1 = ilen;
    rxDescr->pd.orgBufPtr = bufPhys; rxDescr->pd.orgBufLen = ilen;

    sa2ul_dma_flush(txDescr, SA2UL_DESC_SIZE);
    sa2ul_dma_flush(rxDescr, SA2UL_DESC_SIZE);
    sa2ul_dma_flush(gPool->buf, ilen);

    /* free rx descriptor first, then the tx packet */
    if (gRxRing.Push(&gRxRing, false, rxPhys) != Success) {
        SA2UL_LOG("sa2ul_driver: rx ring push failed\n");
        sa2ul_dma_broken();
        return -1;
    }
    if (gTxRing.Push(&gTxRing, false, txPhys) != Success) {
        SA2UL_LOG("sa2ul_driver: tx ring push failed\n");
        sa2ul_dma_broken();
        return -1;
    }

    /* Wait for both the rx completion and the tx descriptor's return */
    for (waited = 0; waited < SA2UL_POLL_LIMIT && !(gotRx && gotTx); waited++) {
        if (!gotRx && gRxCqRing.Pop(&gRxCqRing, false, &phys) == Success) {
            if ((phys & SA2UL_DESC_ADDR_MASK) != rxPhys) {
                SA2UL_LOG("sa2ul_driver: unexpected rx descriptor 0x%lx\n",
                        (unsigned long)phys);
                sa2ul_dma_broken();
                return -1;
            }
            gotRx = 1;
        }
        if (!gotTx && gTxCqRing.Pop(&gTxCqRing, false, &phys) == Success) {
            if ((phys & SA2UL_DESC_ADDR_MASK) != txPhys) {
                SA2UL_LOG("sa2ul_driver: unexpected tx descriptor 0x%lx\n",
                        (unsigned long)phys);
                sa2ul_dma_broken();
                return -1;
            }
            gotTx = 1;
        }
    }
    if (!(gotRx && gotTx)) {
        /* Descriptors are still owned by the DMA; stop using the engine
         * (callers fall back to software) rather than reuse them. */
        SA2UL_LOG("sa2ul_driver: timed out (rx %s, tx %s); disabling SA2UL\n",
                gotRx ? "done" : "pending", gotTx ? "done" : "pending");
        sa2ul_dma_broken();
        return -1;
    }

    sa2ul_dma_invalidate(rxDescr, SA2UL_DESC_SIZE);
    sa2ul_dma_invalidate(gPool->buf, ilen);

    reg = FEXT(rxDescr->pd.pktInfo1, UDMAP_CPPI5_PD_PKTINFO1_PSFLGS_SHIFT,
            UDMAP_CPPI5_PD_PKTINFO1_PSFLGS_MASK);
    if (reg != 0u) {
        SA2UL_LOG("sa2ul_driver: SA2UL protocol-specific error flags 0x%lx\n", (unsigned long)reg);
        return -1;
    }

    reg = FEXT(rxDescr->pd.descInfo, PKTDMA_CPPI5_PD_DESCINFO_PKTLEN_SHIFT,
            PKTDMA_CPPI5_PD_DESCINFO_PKTLEN_MASK);
    if (reg != ilen) {
        SA2UL_LOG("sa2ul_driver: rx packet length %lu, expected %lu\n",
                (unsigned long)reg, (unsigned long)ilen);
        return -1;
    }

    if (trailerBytes != 0u) {
        uint32_t trailer[SA2UL_MAX_HASH_SIZE_BYTES / 4u];

        reg = FEXT(rxDescr->pd.descInfo, PKTDMA_CPPI5_PD_DESCINFO_PSWCNT_SHIFT,
                PKTDMA_CPPI5_PD_DESCINFO_PSWCNT_MASK);
        if ((reg << 2) != trailerBytes) {
            uint32_t i;
            SA2UL_LOG("sa2ul_driver: unexpected trailer length %lu "
                    "(expected %lu, descInfo 0x%08lx)\n",
                    (unsigned long)(reg << 2), (unsigned long)trailerBytes,
                    (unsigned long)rxDescr->pd.descInfo);
            for (i = 0; i < reg && i < 16u; i++) {
                SA2UL_LOG("  ps[%lu] = 0x%08lx\n", (unsigned long)i,
                        (unsigned long)rxDescr->psData.trailerData[i]);
            }
            return -1;
        }
        memcpy(trailer, &rxDescr->psData.trailerData[0], trailerBytes);
        sa2ul_u32_le_to_u8(TrailerOut, trailer, trailerBytes);
    }

    return 0;
}

/* Like TI's SA2UL_contextFree(): don't leave key material in DMA memory */
static void sa2ul_context_wipe(volatile struct Sa2ulContext *ctxObj)
{
    memset((void *)ctxObj, 0, sizeof(*ctxObj));
    sa2ul_dma_flush(ctxObj, sizeof(*ctxObj));
}

static void sa2ul_wipe(void *p, size_t len)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (len--) {
        *v++ = 0;
    }
}

static int sa2ul_gcm_hash_key(volatile struct Sa2ulContext *ctx,
        const struct Sa2ulAesParams *gcmPrms, uint8_t H[SA2UL_GHASH_LENGTH_BYTES])
{
    struct Sa2ulAesParams ecb;
    uint8_t unused[SA2UL_MAX_HASH_SIZE_BYTES];
    int ret;

    memset(&ecb, 0, sizeof(ecb));
    ecb.encMode = SA2UL_ENC_MODE_ECB;
    ecb.encDirection = SA2UL_ENC_DIR_ENCRYPT;
    ecb.encKeySize = gcmPrms->encKeySize;
    memcpy(ecb.key, gcmPrms->key, sizeof(ecb.key));
    ecb.inputLen = SA2UL_GHASH_LENGTH_BYTES;

    memset(gPool->buf, 0, SA2UL_GHASH_LENGTH_BYTES);
    ret = sa2ul_context_alloc(ctx, &ecb);
    if (ret == 0) {
        ret = sa2ul_context_process(ctx, SA2UL_GHASH_LENGTH_BYTES, unused);
    }
    if (ret == 0) {
        memcpy(H, gPool->buf, SA2UL_GHASH_LENGTH_BYTES);
    }
    sa2ul_context_wipe(ctx);
    sa2ul_wipe(&ecb, sizeof(ecb));
    return ret;
}

/* Top-level entry point -- called by sa2ul_iodevice_server.c with the
 * request already copied out of the Task-shared page. Data is the kernel
 * mapping of the shared data page (CPU access only, never DMA'd). */
int sa2ul_driver_aes(struct Sa2ulCtrl *Ctrl, struct Sa2ulData *Data)
{
    struct Sa2ulAesParams prms;
    volatile struct Sa2ulContext *ctx;
    uint8_t gcmTag[SA2UL_MAX_HASH_SIZE_BYTES];
    uint32_t tagSz = 0;

    if (Ctrl->sz > SA2UL_MAX_BUF || Ctrl->sz == 0u ||
            (Ctrl->keyBytes != 16u && Ctrl->keyBytes != 24u &&
             Ctrl->keyBytes != 32u)) {
        Ctrl->ret = SA2UL_DRIVER_BAD_ARG;
        return Ctrl->ret;
    }

    memset(&prms, 0, sizeof(prms));
    prms.encKeySize = (Ctrl->keyBytes == 32u) ? SA2UL_ENC_KEYSIZE_256 :
                      (Ctrl->keyBytes == 24u) ? SA2UL_ENC_KEYSIZE_192 :
                                                SA2UL_ENC_KEYSIZE_128;
    memcpy(prms.key, Ctrl->key, Ctrl->keyBytes);
    prms.inputLen = Ctrl->sz;

    switch (Ctrl->op) {
    case SA2UL_OP_AES_ECB_ENCRYPT:
    case SA2UL_OP_AES_ECB_DECRYPT:
        prms.encMode = SA2UL_ENC_MODE_ECB;
        prms.encDirection = (Ctrl->op == SA2UL_OP_AES_ECB_ENCRYPT) ?
                SA2UL_ENC_DIR_ENCRYPT : SA2UL_ENC_DIR_DECRYPT;
        break;
    case SA2UL_OP_AES_CBC_ENCRYPT:
    case SA2UL_OP_AES_CBC_DECRYPT:
        prms.encMode = SA2UL_ENC_MODE_CBC;
        prms.encDirection = (Ctrl->op == SA2UL_OP_AES_CBC_ENCRYPT) ?
                SA2UL_ENC_DIR_ENCRYPT : SA2UL_ENC_DIR_DECRYPT;
        memcpy(prms.iv, Ctrl->iv, SA2UL_MAX_IV_SIZE_BYTES);
        break;
    case SA2UL_OP_AES_GCM_ENCRYPT:
    case SA2UL_OP_AES_GCM_DECRYPT:
        tagSz = Ctrl->tagSz;
        if (Ctrl->ivSz != SA2UL_MAX_IV_SIZE_BYTES_GCM ||
                Ctrl->aadSz > SA2UL_MAX_AAD_SIZE_BYTES ||
                tagSz == 0u || tagSz > SA2UL_AES_GCM_AUTHTAG_SIZE_IN_BYTES) {
            sa2ul_wipe(&prms, sizeof(prms));
            Ctrl->ret = SA2UL_DRIVER_BAD_ARG;
            return Ctrl->ret;
        }
        prms.encMode = SA2UL_ENC_MODE_GCM;
        prms.encDirection = (Ctrl->op == SA2UL_OP_AES_GCM_ENCRYPT) ?
                SA2UL_ENC_DIR_ENCRYPT : SA2UL_ENC_DIR_DECRYPT;
        memcpy(prms.iv, Ctrl->iv, SA2UL_MAX_IV_SIZE_BYTES_GCM);
        memcpy(prms.aad, Ctrl->aad, Ctrl->aadSz);
        prms.aadLen = Ctrl->aadSz;
        break;
    default:
        sa2ul_wipe(&prms, sizeof(prms));
        Ctrl->ret = SA2UL_DRIVER_BAD_ARG;
        return Ctrl->ret;
    }

    sa2ul_lock();
    if (!gSa2ulReady) {
        Ctrl->ret = SA2UL_DRIVER_NOT_READY;
        goto out;
    }
    ctx = &gPool->ctx;
    Ctrl->ret = SA2UL_DRIVER_HW_ERROR;

    if (prms.encMode == SA2UL_ENC_MODE_GCM) {
        if (Ctrl->ghashValid) {
            /* H cached by the Task from an earlier call with this key */
            memcpy(prms.ghash, Ctrl->ghash, SA2UL_GHASH_LENGTH_BYTES);
        }
        else {
            if (sa2ul_gcm_hash_key(ctx, &prms, prms.ghash) != 0) {
                goto out;
            }
            memcpy(Ctrl->ghash, prms.ghash, SA2UL_GHASH_LENGTH_BYTES);
            Ctrl->ghashValid = 1u;
        }
    }

    memcpy(gPool->buf, Data->buf, Ctrl->sz);
    if (sa2ul_context_alloc(ctx, &prms) != 0 ||
            sa2ul_context_process(ctx, Ctrl->sz, gcmTag) != 0) {
        sa2ul_context_wipe(ctx);
        goto out;
    }
    sa2ul_context_wipe(ctx);

    if (Ctrl->op == SA2UL_OP_AES_GCM_ENCRYPT) {
        memcpy(Ctrl->tagOut, gcmTag, tagSz);
    }
    else if (Ctrl->op == SA2UL_OP_AES_GCM_DECRYPT) {
        uint8_t diff = 0;
        uint32_t i;
        for (i = 0; i < tagSz; i++) {
            diff |= (uint8_t)(Ctrl->tagIn[i] ^ gcmTag[i]);
        }
        if (diff != 0u) {
            /* don't release unauthenticated plaintext */
            Ctrl->ret = SA2UL_DRIVER_AUTH_FAILED;
            goto out;
        }
    }

    memcpy(Data->buf, gPool->buf, Ctrl->sz);
    Ctrl->ret = SA2UL_DRIVER_OK;

out:
    if (gPool != NULL) {
        sa2ul_wipe(gPool->buf, Ctrl->sz);
    }
    sa2ul_unlock();
    sa2ul_wipe(&prms, sizeof(prms));
    sa2ul_wipe(gcmTag, sizeof(gcmTag));
    return Ctrl->ret;
}

/* SHA-1/SHA-224/SHA-256/SHA-384/SHA-512, one-shot */
int sa2ul_driver_sha(struct Sa2ulCtrl *Ctrl, struct Sa2ulData *Data)
{
    volatile struct Sa2ulContext *ctx;
    uint8_t digest[SA2UL_MAX_HASH_SIZE_BYTES];
    uint8_t hashAlg;

    if (Ctrl->sz > SA2UL_MAX_BUF || Ctrl->sz == 0u) {
        Ctrl->ret = SA2UL_DRIVER_BAD_ARG;
        return Ctrl->ret;
    }

    switch (Ctrl->op) {
        case SA2UL_OP_SHA1:   hashAlg = SA2UL_HASH_ALG_SHA1;     break;
        case SA2UL_OP_SHA224: hashAlg = SA2UL_HASH_ALG_SHA2_224; break;
        case SA2UL_OP_SHA256: hashAlg = SA2UL_HASH_ALG_SHA2_256; break;
        case SA2UL_OP_SHA384: hashAlg = SA2UL_HASH_ALG_SHA2_384; break;
        case SA2UL_OP_SHA512: hashAlg = SA2UL_HASH_ALG_SHA2_512; break;
        default:
            Ctrl->ret = SA2UL_DRIVER_BAD_ARG;
            return Ctrl->ret;
    }

    sa2ul_lock();
    if (!gSa2ulReady) {
        Ctrl->ret = SA2UL_DRIVER_NOT_READY;
        goto out;
    }
    ctx = &gPool->ctx;
    Ctrl->ret = SA2UL_DRIVER_HW_ERROR;

    memcpy(gPool->buf, Data->buf, Ctrl->sz);
    if (sa2ul_context_alloc_auth(ctx, hashAlg, Ctrl->sz) != 0 ||
            sa2ul_context_process(ctx, Ctrl->sz, digest) != 0) {
        sa2ul_context_wipe(ctx);
        goto out;
    }
    sa2ul_context_wipe(ctx);

    memcpy(Ctrl->digestOut, digest, gSa2ulHashSizeBytes[hashAlg & 7u]);
    Ctrl->ret = SA2UL_DRIVER_OK;

out:
    if (gPool != NULL) {
        sa2ul_wipe(gPool->buf, Ctrl->sz);
    }
    sa2ul_unlock();
    return Ctrl->ret;
}
