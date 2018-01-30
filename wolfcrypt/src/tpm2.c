/* tpm2.c
 *
 * Copyright (C) 2006-2017 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_TPM2

#include <wolfssl/wolfcrypt/tpm2.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#define cpu_to_be16 ByteReverseWord16
#define cpu_to_be32 ByteReverseWord32
#define cpu_to_be64 ByteReverseWord64
#define be16_to_cpu ByteReverseWord16
#define be32_to_cpu ByteReverseWord32
#define be64_to_cpu ByteReverseWord64


/* Local Variables */
static TPM2_CTX* gActiveTPM;


/* Local Functions */
static INLINE TPM2_CTX* TPM2_GetActiveCtx(void)
{
    return gActiveTPM;
}

static TPM_RC TPM2_AcquireLock(TPM2_CTX* ctx)
{
#ifdef SINGLE_THREADED
    (void)ctx;
#else
    int ret = wc_LockMutex(&ctx->hwLock);
    if (ret != 0)
        return TPM_RC_FAILURE;
#endif
    return TPM_RC_SUCCESS;
}

static void TPM2_ReleaseLock(TPM2_CTX* ctx)
{
#ifdef SINGLE_THREADED
    (void)ctx;
#else
    wc_UnLockMutex(&ctx->hwLock);
#endif
}



/******************************************************************************/
/* --- BEGIN TPM Interface Specification (TIS) Layer */
/******************************************************************************/
typedef struct TPM2_HEADER {
    UINT16 tag;
    UINT32 size;
    union {
        UINT32 code;
        TPM_CC cc;
        TPM_RC rc;
    };
} WOLFSSL_PACK TPM2_HEADER;

#define TPM_TIS_SPI_READ        0x80
#define TPM_TIS_SPI_WRITE       0x00

enum tpm_tis_access {
    TPM_ACCESS_VALID            = 0x80,
    TPM_ACCESS_ACTIVE_LOCALITY  = 0x20,
    TPM_ACCESS_REQUEST_PENDING  = 0x04,
    TPM_ACCESS_REQUEST_USE      = 0x02,
};

enum tpm_tis_status {
    TPM_STS_VALID               = 0x80,
    TPM_STS_COMMAND_READY       = 0x40,
    TPM_STS_GO                  = 0x20,
    TPM_STS_DATA_AVAIL          = 0x10,
    TPM_STS_DATA_EXPECT         = 0x08,
    TPM_STS_SELF_TEST_DONE      = 0x04,
    TPM_STS_RESP_RETRY          = 0x02,
};

enum tpm_tis_int_flags {
    TPM_GLOBAL_INT_ENABLE       = 0x80000000,
    TPM_INTF_BURST_COUNT_STATIC = 0x100,
    TPM_INTF_CMD_READY_INT      = 0x080,
    TPM_INTF_INT_EDGE_FALLING   = 0x040,
    TPM_INTF_INT_EDGE_RISING    = 0x020,
    TPM_INTF_INT_LEVEL_LOW      = 0x010,
    TPM_INTF_INT_LEVEL_HIGH     = 0x008,
    TPM_INTF_LOC_CHANGE_INT     = 0x004,
    TPM_INTF_STS_VALID_INT      = 0x002,
    TPM_INTF_DATA_AVAIL_INT     = 0x001,
};

#define TPM_ACCESS(l)           (0x0000 | ((l) << 12))
#define TPM_INT_ENABLE(l)       (0x0008 | ((l) << 12))
#define TPM_INT_VECTOR(l)       (0x000C | ((l) << 12))
#define TPM_INT_STATUS(l)       (0x0010 | ((l) << 12))
#define TPM_INTF_CAPS(l)        (0x0014 | ((l) << 12))
#define TPM_STS(l)              (0x0018 | ((l) << 12))
#define TPM_STS3(l)             (0x001b | ((l) << 12))
#define TPM_DATA_FIFO(l)        (0x0024 | ((l) << 12))

#define TPM_DID_VID(l)          (0x0F00 | ((l) << 12))
#define TPM_RID(l)              (0x0F04 | ((l) << 12))


static int TPM2_TIS_SpiRead(TPM2_CTX* ctx, word32 addr, byte* result,
    word32 len)
{
    int rc;
    byte txBuf[MAX_SPI_FRAMESIZE+4];
    byte rxBuf[MAX_SPI_FRAMESIZE+4];

    if (ctx == NULL || result == NULL || len == 0 || len > MAX_SPI_FRAMESIZE)
        return BAD_FUNC_ARG;

    txBuf[0] = TPM_TIS_SPI_READ | ((len & 0xFF) - 1);
    txBuf[1] = (addr>>16) & 0xFF;
    txBuf[2] = (addr>>8)  & 0xFF;
    txBuf[3] = (addr)     & 0xFF;
    XMEMSET(&txBuf[4], 0, len);

    rc = ctx->ioCb(ctx, txBuf, rxBuf, len + 4, ctx->userCtx);

    XMEMCPY(result, &rxBuf[4], len);

    return rc;
}

static int TPM2_TIS_SpiWrite(TPM2_CTX* ctx, word32 addr, const byte* value,
    word32 len)
{
    int rc;
    byte txBuf[MAX_SPI_FRAMESIZE+4];
    byte rxBuf[MAX_SPI_FRAMESIZE+4];

    if (ctx == NULL || value == NULL || len == 0 || len > MAX_SPI_FRAMESIZE)
        return BAD_FUNC_ARG;

    txBuf[0] = TPM_TIS_SPI_WRITE | ((len & 0xFF) - 1);
    txBuf[1] = (addr>>16) & 0xFF;
    txBuf[2] = (addr>>8)  & 0xFF;
    txBuf[3] = (addr)     & 0xFF;
    XMEMCPY(&txBuf[4], value, len);

    rc = ctx->ioCb(ctx, txBuf, rxBuf, len + 4, ctx->userCtx);

    return rc;
}

static int TPM2_TIS_StartupWait(TPM2_CTX* ctx, int timeout)
{
    int rc;
    byte access;

    do {
        rc = TPM2_TIS_SpiRead(ctx, TPM_ACCESS(0), &access, sizeof(access));
        if (access & TPM_ACCESS_VALID)
            return 0;
    } while (rc == TPM_RC_SUCCESS && --timeout > 0);
    return -1;
}

static int TPM2_TIS_CheckLocality(TPM2_CTX* ctx, int locality)
{
    int rc;
    byte access;

    rc = TPM2_TIS_SpiRead(ctx, TPM_ACCESS(locality), &access, sizeof(access));
    if (rc == TPM_RC_SUCCESS &&
        ((access & (TPM_ACCESS_ACTIVE_LOCALITY | TPM_ACCESS_VALID)) ==
                   (TPM_ACCESS_ACTIVE_LOCALITY | TPM_ACCESS_VALID))) {
        ctx->locality = locality;
        return locality;
    }
    return -1;
}

static int TPM2_TIS_RequestLocality(TPM2_CTX* ctx, int timeout)
{
    int rc;
    int locality = 0;
    byte access;

    rc = TPM2_TIS_CheckLocality(ctx, locality);
    if (rc >= 0)
        return rc;

    access = TPM_ACCESS_REQUEST_USE;
    rc = TPM2_TIS_SpiWrite(ctx, TPM_ACCESS(locality), &access, sizeof(access));
    if (rc == TPM_RC_SUCCESS) {
        do {
            rc = TPM2_TIS_CheckLocality(ctx, locality);
            if (rc >= 0)
                return rc;
        } while (--timeout > 0);
    }

    return -1;
}

static int TPM2_TIS_GetInfo(TPM2_CTX* ctx)
{
    word32 reg;
    int rc;

    rc = TPM2_TIS_SpiRead(ctx, TPM_INTF_CAPS(ctx->locality), (byte*)&reg,
        sizeof(reg));
    if (rc == TPM_RC_SUCCESS) {
        ctx->caps = reg;
    }

    rc = TPM2_TIS_SpiRead(ctx, TPM_DID_VID(ctx->locality), (byte*)&reg,
        sizeof(reg));
    if (rc == TPM_RC_SUCCESS) {
        ctx->did_vid = reg;
    }

    reg = 0;
    rc = TPM2_TIS_SpiRead(ctx, TPM_RID(ctx->locality), (byte*)&reg, 1);
    if (rc == TPM_RC_SUCCESS) {
        ctx->rid = reg;
    }

    printf("TPM2: Caps 0x%08x, Did 0x%04x, Vid 0x%04x, Rid 0x%2x \n",
        ctx->caps, ctx->did_vid >> 16, ctx->did_vid & 0xFFFF, ctx->rid);

    return rc;
}

static byte TPM2_TIS_Status(TPM2_CTX* ctx)
{
    byte status = 0;
    TPM2_TIS_SpiRead(ctx, TPM_STS(ctx->locality), &status, sizeof(status));
    return status;
}

static byte TPM2_TIS_WaitForStatus(TPM2_CTX* ctx, byte status, byte status_mask)
{
    byte reg;
    int timeout = TPM_TIMEOUT_TRIES;
    do {
        reg = TPM2_TIS_Status(ctx);
    } while (((reg & status) != status_mask) && --timeout > 0);
    if (timeout <= 0)
        return -1;
    return 0;
}

static int TPM2_TIS_Ready(TPM2_CTX* ctx)
{
    byte status = TPM_STS_COMMAND_READY;
    TPM2_TIS_SpiWrite(ctx, TPM_STS(ctx->locality), &status, sizeof(status));
    return 0;
}

static int TPM2_TIS_GetBurstCount(TPM2_CTX* ctx)
{
    int rc;
    word16 burstCount;

    do {
        rc = TPM2_TIS_SpiRead(ctx, TPM_STS(ctx->locality) + 1,
            (byte*)&burstCount, sizeof(burstCount));
        if (rc != TPM_RC_SUCCESS)
            return -1;
    } while (burstCount == 0);

    if (burstCount > MAX_SPI_FRAMESIZE)
        burstCount = MAX_SPI_FRAMESIZE;

    if (rc == TPM_RC_SUCCESS)
        return burstCount;

    return 0;
}

static int TPM2_TIS_SendCommand(TPM2_CTX* ctx, byte* cmd, word16 cmdSz)
{
    int rc;
    int status, xferSz, pos, burstCount;
    byte access;
    word16 rspSz;

    /* Make sure TPM is ready for command */
    status = TPM2_TIS_Status(ctx);
    if ((status & TPM_STS_COMMAND_READY) == 0) {
        /* Tell TPM chip to expect a command */
        TPM2_TIS_Ready(ctx);

        /* Wait for command ready (TPM_STS_COMMAND_READY = 1) */
        rc = TPM2_TIS_WaitForStatus(ctx, TPM_STS_COMMAND_READY,
                                         TPM_STS_COMMAND_READY);
    }

    /* Write Command */
    pos = 0;
    while (pos < cmdSz) {
        burstCount = TPM2_TIS_GetBurstCount(ctx);
        if (burstCount < 0) {
            rc = burstCount; goto exit;
        }

        xferSz = cmdSz - pos;
        if (xferSz > burstCount)
            xferSz = burstCount;

        rc = TPM2_TIS_SpiWrite(ctx, TPM_DATA_FIFO(ctx->locality), &cmd[pos],
                               xferSz);
        if (rc != TPM_RC_SUCCESS)
            goto exit;
        pos += xferSz;

        if (pos < cmdSz) {
            /* Wait for expect more data (TPM_STS_DATA_EXPECT = 1) */
            rc = TPM2_TIS_WaitForStatus(ctx, TPM_STS_DATA_EXPECT,
                                             TPM_STS_DATA_EXPECT);
            if (rc != 0) {
                printf("TPM2_TIS_SendCommand write expected more data!\n");
                goto exit;
            }
        }
    }

    /* Wait for TPM_STS_DATA_EXPECT = 0 and TPM_STS_VALID = 1 */
    rc = TPM2_TIS_WaitForStatus(ctx, TPM_STS_DATA_EXPECT | TPM_STS_VALID,
                                     TPM_STS_VALID);

    /* Execute Command */
    access = TPM_STS_GO;
    rc = TPM2_TIS_SpiWrite(ctx, TPM_STS(ctx->locality), &access,
                           sizeof(access));
    if (rc != TPM_RC_SUCCESS)
        goto exit;

    /* Read response */
    pos = 0;
    rspSz = sizeof(TPM2_HEADER); /* Read at least TPM header */
    while (pos < rspSz) {
        /* Wait for data to be available (TPM_STS_DATA_AVAIL = 1) */
        rc = TPM2_TIS_WaitForStatus(ctx, TPM_STS_DATA_AVAIL,
                                         TPM_STS_DATA_AVAIL);
        if (rc != 0) {
            printf("TPM2_TIS_SendCommand read no data available!\n");
            goto exit;
        }

        burstCount = TPM2_TIS_GetBurstCount(ctx);
        if (burstCount < 0) {
            rc = burstCount; goto exit;
        }

        xferSz = rspSz - pos;
        if (xferSz > burstCount)
            xferSz = burstCount;

        rc = TPM2_TIS_SpiRead(ctx, TPM_DATA_FIFO(ctx->locality), &cmd[pos],
                              xferSz);
        if (rc != TPM_RC_SUCCESS)
            goto exit;

        pos += xferSz;

        /* Get real response size */
        if (pos == (int)sizeof(TPM2_HEADER)) {
            TPM2_HEADER* header = (TPM2_HEADER*)cmd;
            rspSz = be32_to_cpu(header->size);
        }
    }

    rc = 0;

exit:
    /* Tell TPM we are done */
    TPM2_TIS_Ready(ctx);

    return rc;
}
/******************************************************************************/
/* --- END TPM Interface Layer -- */
/******************************************************************************/



/******************************************************************************/
/* --- BEGIN TPM Packet Assembly / Parsing -- */
/******************************************************************************/

typedef struct TPM2_Packet {
    byte* buf;
    int pos;
    int size;
} TPM2_Packet;

static void TPM2_Packet_Init(TPM2_CTX* ctx, TPM2_Packet* packet) {
    if (ctx && packet) {
        packet->buf  = ctx->cmdBuf;
        packet->pos = sizeof(TPM2_HEADER); /* skip header (fill during finalize) */
        packet->size = sizeof(ctx->cmdBuf);
    }
}

static void TPM2_Packet_AppendU8(TPM2_Packet* packet, UINT8 data) {
    if (packet && (packet->pos + (int)sizeof(UINT8) <= packet->size)) {
        packet->buf[packet->pos] = data;
        packet->pos += sizeof(UINT8);
    }
}
static void TPM2_Packet_AppendU16(TPM2_Packet* packet, UINT16 data) {
    if (packet && (packet->pos + (int)sizeof(UINT16) <= packet->size)) {
        data = cpu_to_be16(data);
        XMEMCPY(&packet->buf[packet->pos], &data, sizeof(UINT16));
        packet->pos += sizeof(UINT16);
    }
}
static void TPM2_Packet_AppendU32(TPM2_Packet* packet, UINT32 data) {
    if (packet && (packet->pos + (int)sizeof(UINT32) <= packet->size)) {
        data = cpu_to_be32(data);
        XMEMCPY(&packet->buf[packet->pos], &data, sizeof(UINT32));
        packet->pos += sizeof(UINT32);
    }
}
static void TPM2_Packet_AppendU64(TPM2_Packet* packet, UINT64 data) {
    if (packet && (packet->pos + (int)sizeof(UINT64) <= packet->size)) {
        data = cpu_to_be64(data);
        XMEMCPY(&packet->buf[packet->pos], &data, sizeof(UINT64));
        packet->pos += sizeof(UINT64);
    }
}
static void TPM2_Packet_AppendS32(TPM2_Packet* packet, INT32 data) {
    if (packet && (packet->pos + (int)sizeof(INT32) <= packet->size)) {
        data = cpu_to_be32(data);
        XMEMCPY(&packet->buf[packet->pos], &data, sizeof(INT32));
        packet->pos += sizeof(INT32);
    }
}
static void TPM2_Packet_AppendBytes(TPM2_Packet* packet, byte* buf, int size) {
    if (packet && (packet->pos + size <= packet->size)) {
        if (buf)
            XMEMCPY(&packet->buf[packet->pos], buf, size);
        packet->pos += size;
    }
}
static void TPM2_Packet_AppendAuth(TPM2_Packet* packet, TPMS_AUTH_COMMAND* auth)
{
    word32 authCmdSz = sizeof(UINT32) + /* session handle */
        sizeof(UINT16) + auth->nonce.size + 1 +  /* none and session attribute */
        sizeof(UINT16) + auth->hmac.size;        /* hmac */
    TPM2_Packet_AppendU32(packet, authCmdSz);
    TPM2_Packet_AppendU32(packet, auth->sessionHandle);
    TPM2_Packet_AppendU16(packet, auth->nonce.size);
    TPM2_Packet_AppendBytes(packet, auth->nonce.buffer, auth->nonce.size);
    TPM2_Packet_AppendU8(packet, auth->sessionAttributes);
    TPM2_Packet_AppendU16(packet, auth->hmac.size);
    TPM2_Packet_AppendBytes(packet, auth->hmac.buffer, auth->hmac.size);
}
static void TPM2_Packet_AppendPCR(TPM2_Packet* packet, TPML_PCR_SELECTION* pcr) {
    int i;
    TPM2_Packet_AppendU32(packet, pcr->count);
    for (i=0; i<(int)pcr->count; i++) {
        TPM2_Packet_AppendU16(packet, pcr->pcrSelections[i].hash);
        TPM2_Packet_AppendU8(packet, pcr->pcrSelections[i].sizeofSelect);
        TPM2_Packet_AppendBytes(packet,
            pcr->pcrSelections[i].pcrSelect,
            pcr->pcrSelections[i].sizeofSelect);
    }
}
static void TPM2_Packet_AppendPublic(TPM2_Packet* packet, TPM2B_PUBLIC* public) {
    TPM2_Packet_AppendU16(packet, public->size);
    TPM2_Packet_AppendU16(packet, public->publicArea.type);
    TPM2_Packet_AppendU16(packet, public->publicArea.nameAlg);
    TPM2_Packet_AppendU32(packet, public->publicArea.objectAttributes);
    TPM2_Packet_AppendU16(packet, public->publicArea.authPolicy.size);
    TPM2_Packet_AppendBytes(packet, public->publicArea.authPolicy.buffer,
        public->publicArea.authPolicy.size);
    switch (public->publicArea.type) {
        case TPM_ALG_KEYEDHASH:
            TPM2_Packet_AppendU16(packet, public->publicArea.parameters.keyedHashDetail.scheme.scheme);
            TPM2_Packet_AppendU16(packet, public->publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg);

            TPM2_Packet_AppendU16(packet, public->publicArea.unique.keyedHash.size);
            TPM2_Packet_AppendBytes(packet, public->publicArea.unique.keyedHash.buffer, public->publicArea.unique.keyedHash.size);
            break;
        case TPM_ALG_SYMCIPHER:
            TPM2_Packet_AppendU16(packet, public->publicArea.parameters.symDetail.sym.algorithm);
            TPM2_Packet_AppendU16(packet, public->publicArea.parameters.symDetail.sym.keyBits.sym);
            TPM2_Packet_AppendU16(packet, public->publicArea.parameters.symDetail.sym.mode.sym);
            break;
        case TPM_ALG_RSA:
            TPM2_Packet_AppendU16(packet, public->publicArea.parameters.rsaDetail.symmetric.algorithm);
            TPM2_Packet_AppendU16(packet, public->publicArea.parameters.rsaDetail.symmetric.keyBits.sym);
            TPM2_Packet_AppendU16(packet, public->publicArea.parameters.rsaDetail.symmetric.mode.sym);

            TPM2_Packet_AppendU16(packet, public->publicArea.parameters.rsaDetail.scheme.scheme);
            TPM2_Packet_AppendU16(packet, public->publicArea.parameters.rsaDetail.scheme.details.anySig.hashAlg);

            TPM2_Packet_AppendU16(packet, public->publicArea.parameters.rsaDetail.keyBits);

            TPM2_Packet_AppendU32(packet, public->publicArea.parameters.rsaDetail.exponent);
            break;
        case TPM_ALG_ECC:
            TPM2_Packet_AppendU16(packet, public->publicArea.parameters.eccDetail.symmetric.algorithm);
            TPM2_Packet_AppendU16(packet, public->publicArea.parameters.eccDetail.symmetric.keyBits.sym);
            TPM2_Packet_AppendU16(packet, public->publicArea.parameters.eccDetail.symmetric.mode.sym);

            TPM2_Packet_AppendU16(packet, public->publicArea.parameters.eccDetail.scheme.scheme);
            TPM2_Packet_AppendU16(packet, public->publicArea.parameters.eccDetail.scheme.details.any.hashAlg);

            TPM2_Packet_AppendU16(packet, public->publicArea.parameters.eccDetail.curveID);

            TPM2_Packet_AppendU16(packet, public->publicArea.parameters.eccDetail.kdf.scheme);
            TPM2_Packet_AppendU16(packet, public->publicArea.parameters.eccDetail.kdf.details.any.hashAlg);
            break;
        default:
            TPM2_Packet_AppendU16(packet, public->publicArea.parameters.asymDetail.symmetric.algorithm);
            TPM2_Packet_AppendU16(packet, public->publicArea.parameters.asymDetail.symmetric.keyBits.sym);
            TPM2_Packet_AppendU16(packet, public->publicArea.parameters.asymDetail.symmetric.mode.sym);

            TPM2_Packet_AppendU16(packet, public->publicArea.parameters.asymDetail.scheme.scheme);
            TPM2_Packet_AppendU16(packet, public->publicArea.parameters.asymDetail.scheme.details.anySig.hashAlg);
            break;
    }
}
static void TPM2_Packet_AppendPoint(TPM2_Packet* packet, TPM2B_ECC_POINT* point) {
    TPM2_Packet_AppendU16(packet, point->size);
    TPM2_Packet_AppendU16(packet, point->point.x.size);
    TPM2_Packet_AppendBytes(packet, point->point.x.buffer, point->point.x.size);
    TPM2_Packet_AppendU16(packet, point->point.y.size);
    TPM2_Packet_AppendBytes(packet, point->point.y.buffer, point->point.y.size);
}

static int TPM2_Packet_Finalize(TPM2_Packet* packet, TPM_ST tag, TPM_CC cc) {
    word32 cmdSz = packet->pos; /* get total packet size */
    packet->pos = 0; /* reset position to front */
    TPM2_Packet_AppendU16(packet, tag);    /* tag */
    TPM2_Packet_AppendU32(packet, cmdSz);  /* command size */
    TPM2_Packet_AppendU32(packet, cc);     /* command code */
    packet->pos = cmdSz; /* restore total size */
    return cmdSz;
}

static void TPM2_Packet_ParseU8(TPM2_Packet* packet, UINT8* data) {
    UINT8 value = 0;
    if (packet && (packet->pos + (int)sizeof(UINT8) <= packet->size)) {
        if (data)
            value = packet->buf[packet->pos];
        packet->pos += sizeof(UINT8);
    }
    if (data)
        *data = value;
}
static void TPM2_Packet_ParseU16(TPM2_Packet* packet, UINT16* data) {
    UINT16 value = 0;
    if (packet && (packet->pos + (int)sizeof(UINT16) <= packet->size)) {
        XMEMCPY(&value, &packet->buf[packet->pos], sizeof(UINT16));
        value = be16_to_cpu(value);
        packet->pos += sizeof(UINT16);
    }
    if (data)
        *data = value;
}
static void TPM2_Packet_ParseU32(TPM2_Packet* packet, UINT32* data) {
    UINT32 value = 0;
    if (packet && (packet->pos + (int)sizeof(UINT32) <= packet->size)) {
        if (data) {
            XMEMCPY(&value, &packet->buf[packet->pos], sizeof(UINT32));
            value = be32_to_cpu(value);
        }
        packet->pos += sizeof(UINT32);
    }
    if (data)
        *data = value;
}
static void TPM2_Packet_ParseU64(TPM2_Packet* packet, UINT64* data) {
    UINT64 value = 0;
    if (packet && (packet->pos + (int)sizeof(UINT64) <= packet->size)) {
        if (data) {
            XMEMCPY(&value, &packet->buf[packet->pos], sizeof(UINT64));
            value = be64_to_cpu(value);
        }
        packet->pos += sizeof(UINT64);
    }
    if (data)
        *data = value;
}
static void TPM2_Packet_ParseBytes(TPM2_Packet* packet, byte* buf, int size) {
    if (packet) {
        if (buf) {
            /* truncate result */
            int sizeToCopy = size;
            if (packet->pos + sizeToCopy > packet->size)
                sizeToCopy = packet->size - packet->pos;
            XMEMCPY(buf, &packet->buf[packet->pos], sizeToCopy);
        }
        packet->pos += size;
    }
}
static TPM_RC TPM2_Packet_Parse(TPM_RC rc, TPM2_Packet* packet) {
    if (rc == TPM_RC_SUCCESS && packet) {
    	UINT32 tmpRc;
        UINT32 respSz;
        packet->pos = 0; /* reset position */
        TPM2_Packet_ParseU16(packet, NULL);     /* tag */
        TPM2_Packet_ParseU32(packet, &respSz);  /* response size */
        TPM2_Packet_ParseU32(packet, &tmpRc);   /* response code */
        packet->size = respSz;
        rc = tmpRc;
    }
    return rc;
}
static void TPM2_Packet_ParsePCR(TPM2_Packet* packet, TPML_PCR_SELECTION* pcr) {
    int i;
    TPM2_Packet_ParseU32(packet, &pcr->count);
    for (i=0; i<(int)pcr->count; i++) {
        TPM2_Packet_ParseU16(packet, &pcr->pcrSelections[i].hash);
        TPM2_Packet_ParseU8(packet, &pcr->pcrSelections[i].sizeofSelect);
        TPM2_Packet_ParseBytes(packet,
            pcr->pcrSelections[i].pcrSelect,
            pcr->pcrSelections[i].sizeofSelect);
    }
}
static void TPM2_Packet_ParsePublic(TPM2_Packet* packet, TPM2B_PUBLIC* public) {
    TPM2_Packet_ParseU16(packet, &public->size);
    TPM2_Packet_ParseU16(packet, &public->publicArea.type);
    TPM2_Packet_ParseU32(packet, &public->publicArea.objectAttributes);
    TPM2_Packet_ParseU16(packet, &public->publicArea.authPolicy.size);
    TPM2_Packet_ParseBytes(packet,
        public->publicArea.authPolicy.buffer,
        public->publicArea.authPolicy.size);
    switch (public->publicArea.type) {
        case TPM_ALG_KEYEDHASH:
            TPM2_Packet_ParseU16(packet, &public->publicArea.parameters.keyedHashDetail.scheme.scheme);
            TPM2_Packet_ParseU16(packet, &public->publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg);

            TPM2_Packet_ParseU16(packet, &public->publicArea.unique.keyedHash.size);
            TPM2_Packet_ParseBytes(packet, public->publicArea.unique.keyedHash.buffer,
                public->publicArea.unique.keyedHash.size);
            break;
        case TPM_ALG_SYMCIPHER:
            TPM2_Packet_ParseU16(packet, &public->publicArea.parameters.symDetail.sym.algorithm);
            TPM2_Packet_ParseU16(packet, &public->publicArea.parameters.symDetail.sym.keyBits.sym);
            TPM2_Packet_ParseU16(packet, &public->publicArea.parameters.symDetail.sym.mode.sym);
            break;
        case TPM_ALG_RSA:
            TPM2_Packet_ParseU16(packet, &public->publicArea.parameters.rsaDetail.symmetric.algorithm);
            TPM2_Packet_ParseU16(packet, &public->publicArea.parameters.rsaDetail.symmetric.keyBits.sym);
            TPM2_Packet_ParseU16(packet, &public->publicArea.parameters.rsaDetail.symmetric.mode.sym);

            TPM2_Packet_ParseU16(packet, &public->publicArea.parameters.rsaDetail.scheme.scheme);
            TPM2_Packet_ParseU16(packet, &public->publicArea.parameters.rsaDetail.scheme.details.anySig.hashAlg);

            TPM2_Packet_ParseU16(packet, &public->publicArea.parameters.rsaDetail.keyBits);

            TPM2_Packet_ParseU32(packet, &public->publicArea.parameters.rsaDetail.exponent);
            break;
        case TPM_ALG_ECC:
            TPM2_Packet_ParseU16(packet, &public->publicArea.parameters.eccDetail.symmetric.algorithm);
            TPM2_Packet_ParseU16(packet, &public->publicArea.parameters.eccDetail.symmetric.keyBits.sym);
            TPM2_Packet_ParseU16(packet, &public->publicArea.parameters.eccDetail.symmetric.mode.sym);

            TPM2_Packet_ParseU16(packet, &public->publicArea.parameters.eccDetail.scheme.scheme);
            TPM2_Packet_ParseU16(packet, &public->publicArea.parameters.eccDetail.scheme.details.any.hashAlg);

            TPM2_Packet_ParseU16(packet, &public->publicArea.parameters.eccDetail.curveID);

            TPM2_Packet_ParseU16(packet, &public->publicArea.parameters.eccDetail.kdf.scheme);
            TPM2_Packet_ParseU16(packet, &public->publicArea.parameters.eccDetail.kdf.details.any.hashAlg);
            break;
        default:
            TPM2_Packet_ParseU16(packet, &public->publicArea.parameters.asymDetail.symmetric.algorithm);
            TPM2_Packet_ParseU16(packet, &public->publicArea.parameters.asymDetail.symmetric.keyBits.sym);
            TPM2_Packet_ParseU16(packet, &public->publicArea.parameters.asymDetail.symmetric.mode.sym);

            TPM2_Packet_ParseU16(packet, &public->publicArea.parameters.asymDetail.scheme.scheme);
            TPM2_Packet_ParseU16(packet, &public->publicArea.parameters.asymDetail.scheme.details.anySig.hashAlg);
            break;
    }
}
static void TPM2_Packet_ParsePoint(TPM2_Packet* packet, TPM2B_ECC_POINT* point) {
    TPM2_Packet_ParseU16(packet, &point->size);
    TPM2_Packet_ParseU16(packet, &point->point.x.size);
    TPM2_Packet_ParseBytes(packet, point->point.x.buffer, point->point.x.size);
    TPM2_Packet_ParseU16(packet, &point->point.y.size);
    TPM2_Packet_ParseBytes(packet, point->point.y.buffer, point->point.y.size);
}


/******************************************************************************/
/* --- END TPM Packet Assembly / Parsing -- */
/******************************************************************************/



/* Send Command Wrapper */
static TPM_RC TPM2_SendCommand(TPM2_CTX* ctx, TPM2_Packet* packet)
{
    if (ctx && packet) {
        byte* cmd = packet->buf;
        word16 cmdSz = packet->pos;
        packet->pos = 0; /* reset size */
        return (TPM_RC)TPM2_TIS_SendCommand(ctx, cmd, cmdSz);
    }
    return TPM_RC_FAILURE;
}

/* Standard TPM API's */
TPM_RC TPM2_Init(TPM2_CTX* ctx, TPM2HalIoCb ioCb, void* userCtx)
{
    TPM_RC rc;

    if (ctx == NULL) {
        return TPM_RC_FAILURE;
    }

    XMEMSET(ctx, 0, sizeof(TPM2_CTX));
    ctx->ioCb = ioCb;
    ctx->userCtx = userCtx;

#ifndef SINGLE_THREADED
    if (wc_InitMutex(&ctx->hwLock) != 0) {
        WOLFSSL_MSG("TPM Mutex Init failed");
        return TPM_RC_FAILURE;
    }
#endif

    /* Startup TIS */
    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {

        /* Set the active TPM global */
        gActiveTPM = ctx;

        /* Wait for chip startup to complete */
        rc = TPM2_TIS_StartupWait(ctx, TPM_TIMEOUT_TRIES);
        if (rc == TPM_RC_SUCCESS) {

            /* Request locality for TPM module */
            rc = TPM2_TIS_RequestLocality(ctx, TPM_TIMEOUT_TRIES);
            if (rc == TPM_RC_SUCCESS) {

                /* Get device information */
                rc = TPM2_TIS_GetInfo(ctx);
            }
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_Startup(Startup_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU16(&packet, in->startupType);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_Startup);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_Shutdown(Shutdown_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU16(&packet, in->shutdownType);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_Shutdown);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}


TPM_RC TPM2_SelfTest(SelfTest_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU8(&packet, in->fullTest);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_SelfTest);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_IncrementalSelfTest(IncrementalSelfTest_In* in,
    IncrementalSelfTest_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        int i;
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->toTest.count);
        for (i=0; i<(int)in->toTest.count; i++) {
            TPM2_Packet_AppendU16(&packet, in->toTest.algorithms[i]);
        }
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS,
            TPM_CC_IncrementalSelfTest);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
            TPM2_Packet_ParseU32(&packet, &out->toDoList.count);
            for (i=0; i<(int)out->toDoList.count; i++) {
                TPM2_Packet_ParseU16(&packet, &out->toDoList.algorithms[i]);
            }
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_GetTestResult(GetTestResult_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_GetTestResult);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
            TPM2_Packet_ParseU16(&packet, &out->outData.size);
            TPM2_Packet_ParseBytes(&packet, out->outData.buffer,
                out->outData.size);
            TPM2_Packet_ParseU16(&packet, &out->testResult);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_GetCapability(GetCapability_In* in, GetCapability_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        int i;
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->capability);
        TPM2_Packet_AppendU32(&packet, in->property);
        TPM2_Packet_AppendU32(&packet, in->propertyCount);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_GetCapability);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
            TPM2_Packet_ParseU8(&packet, &out->moreData);
            TPM2_Packet_ParseU32(&packet, &out->capabilityData.capability);

            switch (out->capabilityData.capability) {
                case TPM_CAP_TPM_PROPERTIES: {
                    TPML_TAGGED_TPM_PROPERTY* prop =
                        &out->capabilityData.data.tpmProperties;
                    TPM2_Packet_ParseU32(&packet, &prop->count);
                    for (i=0; i<(int)prop->count; i++) {
                        TPM2_Packet_ParseU32(&packet,
                            &prop->tpmProperty[i].property);
                        TPM2_Packet_ParseU32(&packet,
                            &prop->tpmProperty[i].value);
                    }
                    break;
                }
                default:
                    printf("Unknown capability type 0x%x\n",
                        (unsigned int)out->capabilityData.capability);
                    rc = -1;
                    break;
            }
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_GetRandom(GetRandom_In* in, GetRandom_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU16(&packet, in->bytesRequested);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_GetRandom);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
            TPM2_Packet_ParseU16(&packet, &out->randomBytes.size);
            TPM2_Packet_ParseBytes(&packet, out->randomBytes.buffer,
                out->randomBytes.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_StirRandom(StirRandom_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU16(&packet, in->inData.size);
        TPM2_Packet_AppendBytes(&packet, in->inData.buffer, in->inData.size);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_StirRandom);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}


TPM_RC TPM2_PCR_Read(PCR_Read_In* in, PCR_Read_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        int i;
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendPCR(&packet, &in->pcrSelectionIn);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_PCR_Read);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParseU32(&packet, &out->pcrUpdateCounter);
            TPM2_Packet_ParsePCR(&packet, &out->pcrSelectionOut);
            TPM2_Packet_ParseU32(&packet, &out->pcrValues.count);
            for (i=0; i<(int)out->pcrValues.count; i++) {
                TPM2_Packet_ParseU16(&packet, &out->pcrValues.digests[i].size);
                TPM2_Packet_ParseBytes(&packet,
                    out->pcrValues.digests[i].buffer,
                    out->pcrValues.digests[i].size);
            }
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PCR_Extend(PCR_Extend_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        int i;
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->pcrHandle);
        TPM2_Packet_AppendAuth(&packet, &in->auth);
        TPM2_Packet_AppendU32(&packet, in->digests.count);
        for (i=0; i<(int)in->digests.count; i++) {
            UINT16 hashAlg = in->digests.digests[i].hashAlg;
            int digestSz = TPM2_GetHashDigestSize(hashAlg);
            TPM2_Packet_AppendU16(&packet, hashAlg);
            TPM2_Packet_AppendBytes(&packet, in->digests.digests[i].digest.H,
                digestSz);
        }
        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_PCR_Extend);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}


TPM_RC TPM2_Create(Create_In* in, Create_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->parentHandle);
        TPM2_Packet_AppendAuth(&packet, &in->auth);

        TPM2_Packet_AppendU16(&packet, in->inSensitive.size);
        TPM2_Packet_AppendU16(&packet, in->inSensitive.sensitive.userAuth.size);
        TPM2_Packet_AppendBytes(&packet, in->inSensitive.sensitive.userAuth.buffer,
            in->inSensitive.sensitive.userAuth.size);
        TPM2_Packet_AppendU16(&packet, in->inSensitive.sensitive.data.size);
        TPM2_Packet_AppendBytes(&packet, in->inSensitive.sensitive.data.buffer,
            in->inSensitive.sensitive.data.size);

        TPM2_Packet_AppendPublic(&packet, &in->inPublic);

        TPM2_Packet_AppendU16(&packet, in->outsideInfo.size);
        TPM2_Packet_AppendBytes(&packet, in->outsideInfo.buffer, in->outsideInfo.size);

        TPM2_Packet_AppendPCR(&packet, &in->creationPCR);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_Create);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParseU16(&packet, &out->outPrivate.size);
            TPM2_Packet_ParseBytes(&packet, out->outPrivate.buffer, out->outPrivate.size);

            TPM2_Packet_ParsePublic(&packet, &out->outPublic);

            TPM2_Packet_ParseU16(&packet, &out->creationData.size);
            TPM2_Packet_ParsePCR(&packet, &out->creationData.creationData.pcrSelect);
            TPM2_Packet_ParseU16(&packet, &out->creationData.creationData.pcrDigest.size);
            TPM2_Packet_ParseBytes(&packet,
                        out->creationData.creationData.pcrDigest.buffer,
                        out->creationData.creationData.pcrDigest.size);
            TPM2_Packet_ParseU8(&packet, &out->creationData.creationData.locality);
            TPM2_Packet_ParseU16(&packet, &out->creationData.creationData.parentNameAlg);
            TPM2_Packet_ParseU16(&packet, &out->creationData.creationData.parentName.size);
            TPM2_Packet_ParseBytes(&packet,
                        out->creationData.creationData.parentName.name,
                        out->creationData.creationData.parentName.size);
            TPM2_Packet_ParseU16(&packet, &out->creationData.creationData.parentQualifiedName.size);
            TPM2_Packet_ParseBytes(&packet,
                        out->creationData.creationData.parentQualifiedName.name,
                        out->creationData.creationData.parentQualifiedName.size);
            TPM2_Packet_ParseU16(&packet, &out->creationData.creationData.outsideInfo.size);
            TPM2_Packet_ParseBytes(&packet,
                        out->creationData.creationData.outsideInfo.buffer,
                        out->creationData.creationData.outsideInfo.size);

            TPM2_Packet_ParseU16(&packet, &out->creationHash.size);
            TPM2_Packet_ParseBytes(&packet,
                        out->creationHash.buffer,
                        out->creationHash.size);

            TPM2_Packet_ParseU16(&packet, &out->creationTicket.tag);
            TPM2_Packet_ParseU32(&packet, &out->creationTicket.hierarchy);
            TPM2_Packet_ParseU16(&packet, &out->creationTicket.digest.size);
            TPM2_Packet_ParseBytes(&packet,
                        out->creationTicket.digest.buffer,
                        out->creationTicket.digest.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_CreatePrimary(CreatePrimary_In* in, CreatePrimary_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->primaryHandle);

        TPM2_Packet_AppendU16(&packet, in->inSensitive.size);
        TPM2_Packet_AppendU16(&packet, in->inSensitive.sensitive.userAuth.size);
        TPM2_Packet_AppendBytes(&packet, in->inSensitive.sensitive.userAuth.buffer,
            in->inSensitive.sensitive.userAuth.size);
        TPM2_Packet_AppendU16(&packet, in->inSensitive.sensitive.data.size);
        TPM2_Packet_AppendBytes(&packet, in->inSensitive.sensitive.data.buffer,
            in->inSensitive.sensitive.data.size);

        TPM2_Packet_AppendPublic(&packet, &in->inPublic);

        TPM2_Packet_AppendU16(&packet, in->outsideInfo.size);
        TPM2_Packet_AppendBytes(&packet, in->outsideInfo.buffer, in->outsideInfo.size);

        TPM2_Packet_AppendPCR(&packet, &in->creationPCR);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_CreatePrimary);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParseU32(&packet, &out->objectHandle);

            TPM2_Packet_ParsePublic(&packet, &out->outPublic);

            TPM2_Packet_ParseU16(&packet, &out->creationData.size);
            TPM2_Packet_ParsePCR(&packet, &out->creationData.creationData.pcrSelect);
            TPM2_Packet_ParseU16(&packet, &out->creationData.creationData.pcrDigest.size);
            TPM2_Packet_ParseBytes(&packet,
                        out->creationData.creationData.pcrDigest.buffer,
                        out->creationData.creationData.pcrDigest.size);
            TPM2_Packet_ParseU8(&packet, &out->creationData.creationData.locality);
            TPM2_Packet_ParseU16(&packet, &out->creationData.creationData.parentNameAlg);
            TPM2_Packet_ParseU16(&packet, &out->creationData.creationData.parentName.size);
            TPM2_Packet_ParseBytes(&packet,
                        out->creationData.creationData.parentName.name,
                        out->creationData.creationData.parentName.size);
            TPM2_Packet_ParseU16(&packet, &out->creationData.creationData.parentQualifiedName.size);
            TPM2_Packet_ParseBytes(&packet,
                        out->creationData.creationData.parentQualifiedName.name,
                        out->creationData.creationData.parentQualifiedName.size);
            TPM2_Packet_ParseU16(&packet, &out->creationData.creationData.outsideInfo.size);
            TPM2_Packet_ParseBytes(&packet,
                        out->creationData.creationData.outsideInfo.buffer,
                        out->creationData.creationData.outsideInfo.size);

            TPM2_Packet_ParseU16(&packet, &out->creationHash.size);
            TPM2_Packet_ParseBytes(&packet,
                        out->creationHash.buffer,
                        out->creationHash.size);

            TPM2_Packet_ParseU16(&packet, &out->creationTicket.tag);
            TPM2_Packet_ParseU32(&packet, &out->creationTicket.hierarchy);
            TPM2_Packet_ParseU16(&packet, &out->creationTicket.digest.size);
            TPM2_Packet_ParseBytes(&packet,
                        out->creationTicket.digest.buffer,
                        out->creationTicket.digest.size);

            TPM2_Packet_ParseU16(&packet, &out->name.size);
            TPM2_Packet_ParseBytes(&packet, out->name.name, out->name.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}


TPM_RC TPM2_Load(Load_In* in, Load_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->parentHandle);
        TPM2_Packet_AppendAuth(&packet, &in->auth);

        TPM2_Packet_AppendU16(&packet, in->inPrivate.size);
        TPM2_Packet_AppendBytes(&packet, in->inPrivate.buffer, in->inPrivate.size);

        TPM2_Packet_AppendPublic(&packet, &in->inPublic);

        TPM2_Packet_Finalize(&packet, TPM_ST_SESSIONS, TPM_CC_Load);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParseU32(&packet, &out->objectHandle);
            TPM2_Packet_ParseU16(&packet, &out->name.size);
            TPM2_Packet_ParseBytes(&packet, out->name.name, out->name.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_FlushContext(FlushContext_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->flushHandle);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_FlushContext);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_Unseal(Unseal_In* in, Unseal_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->itemHandle);
        TPM2_Packet_AppendAuth(&packet, &in->auth);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_Unseal);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParseU16(&packet, &out->outData.size);
            TPM2_Packet_ParseBytes(&packet, out->outData.buffer, out->outData.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_StartAuthSession(StartAuthSession_In* in, StartAuthSession_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->tpmKey);
        TPM2_Packet_AppendU32(&packet, in->bind);
        TPM2_Packet_AppendU16(&packet, in->nonceCaller.size);
        TPM2_Packet_AppendBytes(&packet, in->nonceCaller.buffer, in->nonceCaller.size);

        TPM2_Packet_AppendU16(&packet, in->encryptedSalt.size);
        TPM2_Packet_AppendBytes(&packet, in->encryptedSalt.secret, in->encryptedSalt.size);

        TPM2_Packet_AppendU8(&packet, in->sessionType);

        TPM2_Packet_AppendU16(&packet, in->symmetric.algorithm);
        TPM2_Packet_AppendU16(&packet, in->symmetric.keyBits.sym);
        TPM2_Packet_AppendU16(&packet, in->symmetric.mode.sym);

        TPM2_Packet_AppendU16(&packet, in->authHash);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_StartAuthSession);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParseU32(&packet, &out->sessionHandle);
            TPM2_Packet_ParseU16(&packet, &out->nonceTPM.size);
            TPM2_Packet_ParseBytes(&packet, out->nonceTPM.buffer, out->nonceTPM.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PolicyRestart(PolicyRestart_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->sessionHandle);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_PolicyRestart);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_LoadExternal(LoadExternal_In* in, LoadExternal_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU16(&packet, in->inPrivate.size);
        TPM2_Packet_AppendU16(&packet, in->inPrivate.sensitiveArea.sensitiveType);
        TPM2_Packet_AppendU16(&packet, in->inPrivate.sensitiveArea.authValue.size);
        TPM2_Packet_AppendBytes(&packet,
            in->inPrivate.sensitiveArea.authValue.buffer,
            in->inPrivate.sensitiveArea.authValue.size);
        TPM2_Packet_AppendU16(&packet, in->inPrivate.sensitiveArea.seedValue.size);
        TPM2_Packet_AppendBytes(&packet,
            in->inPrivate.sensitiveArea.seedValue.buffer,
            in->inPrivate.sensitiveArea.seedValue.size);

        TPM2_Packet_AppendU16(&packet, in->inPrivate.sensitiveArea.sensitive.any.size);
        TPM2_Packet_AppendBytes(&packet,
            in->inPrivate.sensitiveArea.sensitive.any.buffer,
            in->inPrivate.sensitiveArea.sensitive.any.size);

        TPM2_Packet_AppendPublic(&packet, &in->inPublic);
        TPM2_Packet_AppendU32(&packet, in->hierarchy);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_LoadExternal);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParseU32(&packet, &out->objectHandle);
            TPM2_Packet_ParseU16(&packet, &out->name.size);
            TPM2_Packet_ParseBytes(&packet, out->name.name, out->name.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_ReadPublic(ReadPublic_In* in, ReadPublic_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->objectHandle);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_ReadPublic);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParsePublic(&packet, &out->outPublic);

            TPM2_Packet_ParseU16(&packet, &out->name.size);
            TPM2_Packet_ParseBytes(&packet, out->name.name, out->name.size);

            TPM2_Packet_ParseU16(&packet, &out->qualifiedName.size);
            TPM2_Packet_ParseBytes(&packet, out->qualifiedName.name, out->qualifiedName.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_ActivateCredential(ActivateCredential_In* in,
    ActivateCredential_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->activateHandle);
        TPM2_Packet_AppendU32(&packet, in->keyHandle);

        TPM2_Packet_AppendU16(&packet, in->credentialBlob.size);
        TPM2_Packet_AppendBytes(&packet, in->credentialBlob.buffer, in->credentialBlob.size);

        TPM2_Packet_AppendU16(&packet, in->secret.size);
        TPM2_Packet_AppendBytes(&packet, in->secret.secret, in->secret.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_ActivateCredential);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParseU16(&packet, &out->certInfo.size);
            TPM2_Packet_ParseBytes(&packet, out->certInfo.buffer, out->certInfo.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_MakeCredential(MakeCredential_In* in, MakeCredential_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->handle);

        TPM2_Packet_AppendU16(&packet, in->credential.size);
        TPM2_Packet_AppendBytes(&packet, in->credential.buffer, in->credential.size);

        TPM2_Packet_AppendU16(&packet, in->objectName.size);
        TPM2_Packet_AppendBytes(&packet, in->objectName.name, in->objectName.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_MakeCredential);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParseU16(&packet, &out->credentialBlob.size);
            TPM2_Packet_ParseBytes(&packet, out->credentialBlob.buffer, out->credentialBlob.size);

            TPM2_Packet_ParseU16(&packet, &out->secret.size);
            TPM2_Packet_ParseBytes(&packet, out->secret.secret, out->secret.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_ObjectChangeAuth(ObjectChangeAuth_In* in, ObjectChangeAuth_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->objectHandle);
        TPM2_Packet_AppendU32(&packet, in->parentHandle);

        TPM2_Packet_AppendU16(&packet, in->newAuth.size);
        TPM2_Packet_AppendBytes(&packet, in->newAuth.buffer, in->newAuth.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_ObjectChangeAuth);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParseU16(&packet, &out->outPrivate.size);
            TPM2_Packet_ParseBytes(&packet, out->outPrivate.buffer, out->outPrivate.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_Duplicate(Duplicate_In* in, Duplicate_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->objectHandle);
        TPM2_Packet_AppendU32(&packet, in->newParentHandle);

        TPM2_Packet_AppendU16(&packet, in->encryptionKeyIn.size);
        TPM2_Packet_AppendBytes(&packet, in->encryptionKeyIn.buffer, in->encryptionKeyIn.size);

        TPM2_Packet_AppendU16(&packet, in->symmetricAlg.algorithm);
        TPM2_Packet_AppendU16(&packet, in->symmetricAlg.keyBits.sym);
        TPM2_Packet_AppendU16(&packet, in->symmetricAlg.mode.sym);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_Duplicate);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParseU16(&packet, &out->encryptionKeyOut.size);
            TPM2_Packet_ParseBytes(&packet, out->encryptionKeyOut.buffer, out->encryptionKeyOut.size);

            TPM2_Packet_ParseU16(&packet, &out->duplicate.size);
            TPM2_Packet_ParseBytes(&packet, out->duplicate.buffer, out->duplicate.size);

            TPM2_Packet_ParseU16(&packet, &out->outSymSeed.size);
            TPM2_Packet_ParseBytes(&packet, out->outSymSeed.secret, out->outSymSeed.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_Rewrap(Rewrap_In* in, Rewrap_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->oldParent);
        TPM2_Packet_AppendU32(&packet, in->newParent);

        TPM2_Packet_AppendU16(&packet, in->inDuplicate.size);
        TPM2_Packet_AppendBytes(&packet, in->inDuplicate.buffer, in->inDuplicate.size);

        TPM2_Packet_AppendU16(&packet, in->name.size);
        TPM2_Packet_AppendBytes(&packet, in->name.name, in->name.size);

        TPM2_Packet_AppendU16(&packet, in->inSymSeed.size);
        TPM2_Packet_AppendBytes(&packet, in->inSymSeed.secret, in->inSymSeed.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_Rewrap);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParseU16(&packet, &out->outDuplicate.size);
            TPM2_Packet_ParseBytes(&packet, out->outDuplicate.buffer, out->outDuplicate.size);

            TPM2_Packet_ParseU16(&packet, &out->outSymSeed.size);
            TPM2_Packet_ParseBytes(&packet, out->outSymSeed.secret, out->outSymSeed.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_Import(Import_In* in, Import_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->parentHandle);

        TPM2_Packet_AppendU16(&packet, in->encryptionKey.size);
        TPM2_Packet_AppendBytes(&packet, in->encryptionKey.buffer, in->encryptionKey.size);

        TPM2_Packet_AppendPublic(&packet, &in->objectPublic);

        TPM2_Packet_AppendU16(&packet, in->duplicate.size);
        TPM2_Packet_AppendBytes(&packet, in->duplicate.buffer, in->duplicate.size);

        TPM2_Packet_AppendU16(&packet, in->inSymSeed.size);
        TPM2_Packet_AppendBytes(&packet, in->inSymSeed.secret, in->inSymSeed.size);

        TPM2_Packet_AppendU16(&packet, in->symmetricAlg.algorithm);
        TPM2_Packet_AppendU16(&packet, in->symmetricAlg.keyBits.sym);
        TPM2_Packet_AppendU16(&packet, in->symmetricAlg.mode.sym);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_Import);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParseU16(&packet, &out->outPrivate.size);
            TPM2_Packet_ParseBytes(&packet, out->outPrivate.buffer, out->outPrivate.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_RSA_Encrypt(RSA_Encrypt_In* in, RSA_Encrypt_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->keyHandle);

        TPM2_Packet_AppendU16(&packet, in->message.size);
        TPM2_Packet_AppendBytes(&packet, in->message.buffer, in->message.size);

        TPM2_Packet_AppendU16(&packet, in->inScheme.scheme);
        TPM2_Packet_AppendU16(&packet, in->inScheme.details.anySig.hashAlg);

        TPM2_Packet_AppendU16(&packet, in->label.size);
        TPM2_Packet_AppendBytes(&packet, in->label.buffer, in->label.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_RSA_Encrypt);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParseU16(&packet, &out->outData.size);
            TPM2_Packet_ParseBytes(&packet, out->outData.buffer, out->outData.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_RSA_Decrypt(RSA_Decrypt_In* in, RSA_Decrypt_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->keyHandle);

        TPM2_Packet_AppendU16(&packet, in->cipherText.size);
        TPM2_Packet_AppendBytes(&packet, in->cipherText.buffer, in->cipherText.size);

        TPM2_Packet_AppendU16(&packet, in->inScheme.scheme);
        TPM2_Packet_AppendU16(&packet, in->inScheme.details.anySig.hashAlg);

        TPM2_Packet_AppendU16(&packet, in->label.size);
        TPM2_Packet_AppendBytes(&packet, in->label.buffer, in->label.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_RSA_Decrypt);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParseU16(&packet, &out->message.size);
            TPM2_Packet_ParseBytes(&packet, out->message.buffer, out->message.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_ECDH_KeyGen(ECDH_KeyGen_In* in, ECDH_KeyGen_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->keyHandle);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_ECDH_KeyGen);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParsePoint(&packet, &out->zPoint);
            TPM2_Packet_ParsePoint(&packet, &out->pubPoint);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_ECDH_ZGen(ECDH_ZGen_In* in, ECDH_ZGen_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->keyHandle);
        TPM2_Packet_AppendPoint(&packet, &in->inPoint);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_ECDH_ZGen);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParsePoint(&packet, &out->outPoint);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_ECC_Parameters(ECC_Parameters_In* in,
    ECC_Parameters_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU16(&packet, in->curveID);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_ECC_Parameters);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParseU16(&packet, &out->parameters.curveID);
            TPM2_Packet_ParseU16(&packet, &out->parameters.keySize);
            TPM2_Packet_ParseU16(&packet, &out->parameters.kdf.scheme);
            TPM2_Packet_ParseU16(&packet, &out->parameters.kdf.details.any.hashAlg);

            TPM2_Packet_ParseU16(&packet, &out->parameters.sign.scheme);
            TPM2_Packet_ParseU16(&packet, &out->parameters.sign.details.any.hashAlg);

            TPM2_Packet_ParseU16(&packet, &out->parameters.p.size);
            TPM2_Packet_ParseBytes(&packet, out->parameters.p.buffer, out->parameters.p.size);

            TPM2_Packet_ParseU16(&packet, &out->parameters.a.size);
            TPM2_Packet_ParseBytes(&packet, out->parameters.a.buffer, out->parameters.a.size);

            TPM2_Packet_ParseU16(&packet, &out->parameters.b.size);
            TPM2_Packet_ParseBytes(&packet, out->parameters.b.buffer, out->parameters.b.size);

            TPM2_Packet_ParseU16(&packet, &out->parameters.gX.size);
            TPM2_Packet_ParseBytes(&packet, out->parameters.gX.buffer, out->parameters.gX.size);

            TPM2_Packet_ParseU16(&packet, &out->parameters.gY.size);
            TPM2_Packet_ParseBytes(&packet, out->parameters.gY.buffer, out->parameters.gY.size);

            TPM2_Packet_ParseU16(&packet, &out->parameters.n.size);
            TPM2_Packet_ParseBytes(&packet, out->parameters.n.buffer, out->parameters.n.size);

            TPM2_Packet_ParseU16(&packet, &out->parameters.h.size);
            TPM2_Packet_ParseBytes(&packet, out->parameters.h.buffer, out->parameters.h.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_ZGen_2Phase(ZGen_2Phase_In* in, ZGen_2Phase_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->keyA);
        TPM2_Packet_AppendPoint(&packet, &in->inQsB);
        TPM2_Packet_AppendPoint(&packet, &in->inQeB);
        TPM2_Packet_AppendU16(&packet, in->inScheme);
        TPM2_Packet_AppendU16(&packet, in->counter);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_ZGen_2Phase);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParsePoint(&packet, &out->outZ1);
            TPM2_Packet_ParsePoint(&packet, &out->outZ2);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_EncryptDecrypt(EncryptDecrypt_In* in, EncryptDecrypt_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->keyHandle);
        TPM2_Packet_AppendU8(&packet, in->decrypt);
        TPM2_Packet_AppendU16(&packet, in->mode);

        TPM2_Packet_AppendU16(&packet, in->ivIn.size);
        TPM2_Packet_AppendBytes(&packet, in->ivIn.buffer, in->ivIn.size);

        TPM2_Packet_AppendU16(&packet, in->inData.size);
        TPM2_Packet_AppendBytes(&packet, in->inData.buffer, in->inData.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_EncryptDecrypt);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParseU16(&packet, &out->outData.size);
            TPM2_Packet_ParseBytes(&packet, out->outData.buffer, out->outData.size);

            TPM2_Packet_ParseU16(&packet, &out->ivOut.size);
            TPM2_Packet_ParseBytes(&packet, out->ivOut.buffer, out->ivOut.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_EncryptDecrypt2(EncryptDecrypt2_In* in, EncryptDecrypt2_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->keyHandle);

        TPM2_Packet_AppendU16(&packet, in->inData.size);
        TPM2_Packet_AppendBytes(&packet, in->inData.buffer, in->inData.size);

        TPM2_Packet_AppendU8(&packet, in->decrypt);
        TPM2_Packet_AppendU16(&packet, in->mode);

        TPM2_Packet_AppendU16(&packet, in->ivIn.size);
        TPM2_Packet_AppendBytes(&packet, in->ivIn.buffer, in->ivIn.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_EncryptDecrypt2);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParseU16(&packet, &out->outData.size);
            TPM2_Packet_ParseBytes(&packet, out->outData.buffer, out->outData.size);

            TPM2_Packet_ParseU16(&packet, &out->ivOut.size);
            TPM2_Packet_ParseBytes(&packet, out->ivOut.buffer, out->ivOut.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_Hash(Hash_In* in, Hash_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU16(&packet, in->data.size);
        TPM2_Packet_AppendBytes(&packet, in->data.buffer, in->data.size);

        TPM2_Packet_AppendU16(&packet, in->hashAlg);
        TPM2_Packet_AppendU32(&packet, in->hierarchy);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_Hash);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParseU16(&packet, &out->outHash.size);
            TPM2_Packet_ParseBytes(&packet, out->outHash.buffer, out->outHash.size);

            TPM2_Packet_ParseU16(&packet, &out->validation.tag);
            TPM2_Packet_ParseU32(&packet, &out->validation.hierarchy);

            TPM2_Packet_ParseU16(&packet, &out->validation.digest.size);
            TPM2_Packet_ParseBytes(&packet, out->validation.digest.buffer, out->validation.digest.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_HMAC(HMAC_In* in, HMAC_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->handle);

        TPM2_Packet_AppendU16(&packet, in->buffer.size);
        TPM2_Packet_AppendBytes(&packet, in->buffer.buffer, in->buffer.size);

        TPM2_Packet_AppendU16(&packet, in->hashAlg);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_HMAC);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParseU16(&packet, &out->outHMAC.size);
            TPM2_Packet_ParseBytes(&packet, out->outHMAC.buffer, out->outHMAC.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_HMAC_Start(HMAC_Start_In* in, HMAC_Start_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->handle);

        TPM2_Packet_AppendU16(&packet, in->auth.size);
        TPM2_Packet_AppendBytes(&packet, in->auth.buffer, in->auth.size);

        TPM2_Packet_AppendU16(&packet, in->hashAlg);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_HMAC_Start);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParseU32(&packet, &out->sequenceHandle);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_HashSequenceStart(HashSequenceStart_In* in,
    HashSequenceStart_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU16(&packet, in->auth.size);
        TPM2_Packet_AppendBytes(&packet, in->auth.buffer, in->auth.size);

        TPM2_Packet_AppendU16(&packet, in->hashAlg);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_HashSequenceStart);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParseU32(&packet, &out->sequenceHandle);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_SequenceUpdate(SequenceUpdate_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->sequenceHandle);

        TPM2_Packet_AppendU16(&packet, in->buffer.size);
        TPM2_Packet_AppendBytes(&packet, in->buffer.buffer, in->buffer.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_SequenceUpdate);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_SequenceComplete(SequenceComplete_In* in, SequenceComplete_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->sequenceHandle);

        TPM2_Packet_AppendU16(&packet, in->buffer.size);
        TPM2_Packet_AppendBytes(&packet, in->buffer.buffer, in->buffer.size);

        TPM2_Packet_AppendU32(&packet, in->hierarchy);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_SequenceComplete);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParseU16(&packet, &out->result.size);
            TPM2_Packet_ParseBytes(&packet, out->result.buffer, out->result.size);

            TPM2_Packet_ParseU16(&packet, &out->validation.tag);
            TPM2_Packet_ParseU32(&packet, &out->validation.hierarchy);

            TPM2_Packet_ParseU16(&packet, &out->validation.digest.size);
            TPM2_Packet_ParseBytes(&packet, out->validation.digest.buffer, out->validation.digest.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_EventSequenceComplete(EventSequenceComplete_In* in,
    EventSequenceComplete_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->pcrHandle);
        TPM2_Packet_AppendU32(&packet, in->sequenceHandle);

        TPM2_Packet_AppendU16(&packet, in->buffer.size);
        TPM2_Packet_AppendBytes(&packet, in->buffer.buffer, in->buffer.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_EventSequenceComplete);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            int i, digestSz;
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParseU32(&packet, &out->results.count);
            for (i=0; i<(int)out->results.count; i++) {
                TPM2_Packet_ParseU16(&packet, &out->results.digests[i].hashAlg);
                digestSz = TPM2_GetHashDigestSize(out->results.digests[i].hashAlg);
                TPM2_Packet_ParseBytes(&packet, out->results.digests[i].digest.H, digestSz);
            }
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_Certify(Certify_In* in, Certify_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->objectHandle);
        TPM2_Packet_AppendU32(&packet, in->signHandle);

        TPM2_Packet_AppendU16(&packet, in->qualifyingData.size);
        TPM2_Packet_AppendBytes(&packet, in->qualifyingData.buffer, in->qualifyingData.size);

        TPM2_Packet_AppendU16(&packet, in->inScheme.scheme);
        TPM2_Packet_AppendU16(&packet, in->inScheme.details.any.hashAlg);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_Certify);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParseU16(&packet, &out->certifyInfo.size);
            TPM2_Packet_ParseBytes(&packet, out->certifyInfo.attestationData, out->certifyInfo.size);

            TPM2_Packet_ParseU16(&packet, &out->signature.sigAlgo);
            TPM2_Packet_ParseU16(&packet, &out->signature.signature.any.hashAlg);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_CertifyCreation(CertifyCreation_In* in, CertifyCreation_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->signHandle);
        TPM2_Packet_AppendU32(&packet, in->objectHandle);

        TPM2_Packet_AppendU16(&packet, in->qualifyingData.size);
        TPM2_Packet_AppendBytes(&packet, in->qualifyingData.buffer, in->qualifyingData.size);

        TPM2_Packet_AppendU16(&packet, in->creationHash.size);
        TPM2_Packet_AppendBytes(&packet, in->creationHash.buffer, in->creationHash.size);

        TPM2_Packet_AppendU16(&packet, in->inScheme.scheme);
        TPM2_Packet_AppendU16(&packet, in->inScheme.details.any.hashAlg);

        TPM2_Packet_AppendU16(&packet, in->creationTicket.tag);
        TPM2_Packet_AppendU32(&packet, in->creationTicket.hierarchy);
        TPM2_Packet_AppendU16(&packet, in->creationTicket.digest.size);
        TPM2_Packet_AppendBytes(&packet,
                    in->creationTicket.digest.buffer,
                    in->creationTicket.digest.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_CertifyCreation);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParseU16(&packet, &out->certifyInfo.size);
            TPM2_Packet_ParseBytes(&packet, out->certifyInfo.attestationData, out->certifyInfo.size);

            TPM2_Packet_ParseU16(&packet, &out->signature.sigAlgo);
            TPM2_Packet_ParseU16(&packet, &out->signature.signature.any.hashAlg);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_Quote(Quote_In* in, Quote_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->signHandle);

        TPM2_Packet_AppendU16(&packet, in->qualifyingData.size);
        TPM2_Packet_AppendBytes(&packet, in->qualifyingData.buffer, in->qualifyingData.size);

        TPM2_Packet_AppendU16(&packet, in->inScheme.scheme);
        TPM2_Packet_AppendU16(&packet, in->inScheme.details.any.hashAlg);

        TPM2_Packet_AppendPCR(&packet, &in->PCRselect);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_Quote);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParseU16(&packet, &out->quoted.size);
            TPM2_Packet_ParseBytes(&packet, out->quoted.attestationData, out->quoted.size);

            TPM2_Packet_ParseU16(&packet, &out->signature.sigAlgo);
            TPM2_Packet_ParseU16(&packet, &out->signature.signature.any.hashAlg);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_GetSessionAuditDigest(GetSessionAuditDigest_In* in,
    GetSessionAuditDigest_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->privacyAdminHandle);
        TPM2_Packet_AppendU32(&packet, in->signHandle);
        TPM2_Packet_AppendU32(&packet, in->sessionHandle);

        TPM2_Packet_AppendU16(&packet, in->qualifyingData.size);
        TPM2_Packet_AppendBytes(&packet, in->qualifyingData.buffer, in->qualifyingData.size);

        TPM2_Packet_AppendU16(&packet, in->inScheme.scheme);
        TPM2_Packet_AppendU16(&packet, in->inScheme.details.any.hashAlg);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_GetSessionAuditDigest);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParseU16(&packet, &out->auditInfo.size);
            TPM2_Packet_ParseBytes(&packet, out->auditInfo.attestationData, out->auditInfo.size);

            TPM2_Packet_ParseU16(&packet, &out->signature.sigAlgo);
            TPM2_Packet_ParseU16(&packet, &out->signature.signature.any.hashAlg);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_GetCommandAuditDigest(GetCommandAuditDigest_In* in,
    GetCommandAuditDigest_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->privacyHandle);
        TPM2_Packet_AppendU32(&packet, in->signHandle);

        TPM2_Packet_AppendU16(&packet, in->qualifyingData.size);
        TPM2_Packet_AppendBytes(&packet, in->qualifyingData.buffer, in->qualifyingData.size);

        TPM2_Packet_AppendU16(&packet, in->inScheme.scheme);
        TPM2_Packet_AppendU16(&packet, in->inScheme.details.any.hashAlg);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_GetCommandAuditDigest);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParseU16(&packet, &out->auditInfo.size);
            TPM2_Packet_ParseBytes(&packet, out->auditInfo.attestationData, out->auditInfo.size);

            TPM2_Packet_ParseU16(&packet, &out->signature.sigAlgo);
            TPM2_Packet_ParseU16(&packet, &out->signature.signature.any.hashAlg);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_GetTime(GetTime_In* in, GetTime_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->privacyAdminHandle);
        TPM2_Packet_AppendU32(&packet, in->signHandle);

        TPM2_Packet_AppendU16(&packet, in->qualifyingData.size);
        TPM2_Packet_AppendBytes(&packet, in->qualifyingData.buffer, in->qualifyingData.size);

        TPM2_Packet_AppendU16(&packet, in->inScheme.scheme);
        TPM2_Packet_AppendU16(&packet, in->inScheme.details.any.hashAlg);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_GetTime);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParseU16(&packet, &out->timeInfo.size);
            TPM2_Packet_ParseBytes(&packet, out->timeInfo.attestationData, out->timeInfo.size);

            TPM2_Packet_ParseU16(&packet, &out->signature.sigAlgo);
            TPM2_Packet_ParseU16(&packet, &out->signature.signature.any.hashAlg);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_Commit(Commit_In* in, Commit_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->signHandle);
        TPM2_Packet_AppendPoint(&packet, &in->P1);

        TPM2_Packet_AppendU16(&packet, in->s2.size);
        TPM2_Packet_AppendBytes(&packet, in->s2.buffer, in->s2.size);

        TPM2_Packet_AppendU16(&packet, in->y2.size);
        TPM2_Packet_AppendBytes(&packet, in->y2.buffer, in->y2.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_Commit);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParsePoint(&packet, &out->K);
            TPM2_Packet_ParsePoint(&packet, &out->L);
            TPM2_Packet_ParsePoint(&packet, &out->E);
            TPM2_Packet_ParseU16(&packet, &out->counter);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_EC_Ephemeral(EC_Ephemeral_In* in, EC_Ephemeral_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->curveID);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_EC_Ephemeral);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParsePoint(&packet, &out->Q);
            TPM2_Packet_ParseU16(&packet, &out->counter);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_VerifySignature(VerifySignature_In* in,
    VerifySignature_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->keyHandle);

        TPM2_Packet_AppendU16(&packet, in->digest.size);
        TPM2_Packet_AppendBytes(&packet, in->digest.buffer, in->digest.size);

        TPM2_Packet_AppendU16(&packet, in->signature.sigAlgo);
        TPM2_Packet_AppendU16(&packet, in->signature.signature.any.hashAlg);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_VerifySignature);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParseU16(&packet, &out->validation.tag);
            TPM2_Packet_ParseU32(&packet, &out->validation.hierarchy);
            TPM2_Packet_ParseU16(&packet, &out->validation.digest.size);
            TPM2_Packet_ParseBytes(&packet,
                        out->validation.digest.buffer,
                        out->validation.digest.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_Sign(Sign_In* in, Sign_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->keyHandle);

        TPM2_Packet_AppendU16(&packet, in->digest.size);
        TPM2_Packet_AppendBytes(&packet, in->digest.buffer, in->digest.size);

        TPM2_Packet_AppendU16(&packet, in->inScheme.scheme);
        TPM2_Packet_AppendU16(&packet, in->inScheme.details.any.hashAlg);

        TPM2_Packet_AppendU16(&packet, in->validation.tag);
        TPM2_Packet_AppendU32(&packet, in->validation.hierarchy);

        TPM2_Packet_AppendU16(&packet, in->validation.digest.size);
        TPM2_Packet_AppendBytes(&packet, in->validation.digest.buffer, in->validation.digest.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_Sign);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParseU16(&packet, &out->signature.sigAlgo);
            TPM2_Packet_ParseU16(&packet, &out->signature.signature.any.hashAlg);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_SetCommandCodeAuditStatus(
    SetCommandCodeAuditStatus_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        int i;
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->auth);
        TPM2_Packet_AppendU16(&packet, in->auditAlg);

        TPM2_Packet_AppendU32(&packet, in->setList.count);
        for (i=0; i<(int)in->setList.count; i++) {
            TPM2_Packet_AppendU32(&packet, in->setList.commandCodes[i]);
        }

        TPM2_Packet_AppendU32(&packet, in->clearList.count);
        for (i=0; i<(int)in->clearList.count; i++) {
            TPM2_Packet_AppendU32(&packet, in->clearList.commandCodes[i]);
        }

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_SetCommandCodeAuditStatus);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PCR_Event(PCR_Event_In* in, PCR_Event_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->pcrHandle);

        TPM2_Packet_AppendU16(&packet, in->eventData.size);
        TPM2_Packet_AppendBytes(&packet, in->eventData.buffer, in->eventData.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_PCR_Event);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            int i;
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParseU32(&packet, &out->digests.count);
            for (i=0; (int)out->digests.count; i++) {
                int digestSz;
                TPM2_Packet_ParseU16(&packet, &out->digests.digests[i].hashAlg);
                digestSz = TPM2_GetHashDigestSize(out->digests.digests[i].hashAlg);
                TPM2_Packet_ParseBytes(&packet, out->digests.digests[i].digest.H, digestSz);
            }
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PCR_Allocate(PCR_Allocate_In* in, PCR_Allocate_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendPCR(&packet, &in->pcrAllocation);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_PCR_Allocate);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParseU8(&packet, &out->allocationSuccess);
            TPM2_Packet_ParseU32(&packet, &out->maxPCR);
            TPM2_Packet_ParseU32(&packet, &out->sizeNeeded);
            TPM2_Packet_ParseU32(&packet, &out->sizeAvailable);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PCR_SetAuthPolicy(PCR_SetAuthPolicy_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authHandle);

        TPM2_Packet_AppendU16(&packet, in->authPolicy.size);
        TPM2_Packet_AppendBytes(&packet, in->authPolicy.buffer, in->authPolicy.size);

        TPM2_Packet_AppendU16(&packet, in->hashAlg);
        TPM2_Packet_AppendU32(&packet, in->pcrNum);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_PCR_SetAuthPolicy);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PCR_SetAuthValue(PCR_SetAuthValue_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->pcrHandle);

        TPM2_Packet_AppendU16(&packet, in->auth.size);
        TPM2_Packet_AppendBytes(&packet, in->auth.buffer, in->auth.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_PCR_SetAuthValue);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PCR_Reset(PCR_Reset_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->pcrHandle);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_PCR_Reset);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PolicySigned(PolicySigned_In* in, PolicySigned_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authObject);
        TPM2_Packet_AppendU32(&packet, in->policySession);

        TPM2_Packet_AppendU16(&packet, in->nonceTPM.size);
        TPM2_Packet_AppendBytes(&packet, in->nonceTPM.buffer, in->nonceTPM.size);

        TPM2_Packet_AppendU16(&packet, in->cpHashA.size);
        TPM2_Packet_AppendBytes(&packet, in->cpHashA.buffer, in->cpHashA.size);

        TPM2_Packet_AppendU16(&packet, in->policyRef.size);
        TPM2_Packet_AppendBytes(&packet, in->policyRef.buffer, in->policyRef.size);

        TPM2_Packet_AppendS32(&packet, in->expiration);

        TPM2_Packet_AppendU16(&packet, in->auth.sigAlgo);
        TPM2_Packet_AppendU16(&packet, in->auth.signature.any.hashAlg);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_PolicySigned);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParseU16(&packet, &out->timeout.size);
            TPM2_Packet_ParseBytes(&packet, out->timeout.buffer, out->timeout.size);

            TPM2_Packet_ParseU16(&packet, &out->policyTicket.tag);
            TPM2_Packet_ParseU32(&packet, &out->policyTicket.hierarchy);
            TPM2_Packet_ParseU16(&packet, &out->policyTicket.digest.size);
            TPM2_Packet_ParseBytes(&packet,
                        out->policyTicket.digest.buffer,
                        out->policyTicket.digest.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PolicySecret(PolicySecret_In* in, PolicySecret_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendU32(&packet, in->policySession);

        TPM2_Packet_AppendU16(&packet, in->nonceTPM.size);
        TPM2_Packet_AppendBytes(&packet, in->nonceTPM.buffer, in->nonceTPM.size);

        TPM2_Packet_AppendU16(&packet, in->cpHashA.size);
        TPM2_Packet_AppendBytes(&packet, in->cpHashA.buffer, in->cpHashA.size);

        TPM2_Packet_AppendU16(&packet, in->policyRef.size);
        TPM2_Packet_AppendBytes(&packet, in->policyRef.buffer, in->policyRef.size);

        TPM2_Packet_AppendS32(&packet, in->expiration);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_PolicySecret);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParseU16(&packet, &out->timeout.size);
            TPM2_Packet_ParseBytes(&packet, out->timeout.buffer, out->timeout.size);

            TPM2_Packet_ParseU16(&packet, &out->policyTicket.tag);
            TPM2_Packet_ParseU32(&packet, &out->policyTicket.hierarchy);
            TPM2_Packet_ParseU16(&packet, &out->policyTicket.digest.size);
            TPM2_Packet_ParseBytes(&packet,
                        out->policyTicket.digest.buffer,
                        out->policyTicket.digest.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PolicyTicket(PolicyTicket_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->policySession);

        TPM2_Packet_AppendU16(&packet, in->timeout.size);
        TPM2_Packet_AppendBytes(&packet, in->timeout.buffer, in->timeout.size);

        TPM2_Packet_AppendU16(&packet, in->cpHashA.size);
        TPM2_Packet_AppendBytes(&packet, in->cpHashA.buffer, in->cpHashA.size);

        TPM2_Packet_AppendU16(&packet, in->policyRef.size);
        TPM2_Packet_AppendBytes(&packet, in->policyRef.buffer, in->policyRef.size);

        TPM2_Packet_AppendU16(&packet, in->authName.size);
        TPM2_Packet_AppendBytes(&packet, in->authName.name, in->authName.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_PolicyTicket);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PolicyOR(PolicyOR_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        int i;
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->policySession);

        TPM2_Packet_AppendU32(&packet, in->pHashList.count);
        for (i=0; i<(int)in->pHashList.count; i++) {
            TPM2_Packet_AppendU16(&packet, in->pHashList.digests[i].size);
            TPM2_Packet_AppendBytes(&packet,
                in->pHashList.digests[i].buffer,
                in->pHashList.digests[i].size);
        }

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_PolicyOR);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PolicyPCR(PolicyPCR_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->policySession);

        TPM2_Packet_AppendU16(&packet, in->pcrDigest.size);
        TPM2_Packet_AppendBytes(&packet, in->pcrDigest.buffer, in->pcrDigest.size);

        TPM2_Packet_AppendPCR(&packet, &in->pcrs);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_PolicyPCR);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PolicyLocality(PolicyLocality_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->policySession);
        TPM2_Packet_AppendU8(&packet, in->locality);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_PolicyLocality);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PolicyNV(PolicyNV_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendU32(&packet, in->nvIndex);
        TPM2_Packet_AppendU32(&packet, in->policySession);

        TPM2_Packet_AppendU16(&packet, in->operandB.size);
        TPM2_Packet_AppendBytes(&packet, in->operandB.buffer, in->operandB.size);

        TPM2_Packet_AppendU16(&packet, in->offset);
        TPM2_Packet_AppendU16(&packet, in->operation);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_PolicyNV);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PolicyCounterTimer(PolicyCounterTimer_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->policySession);

        TPM2_Packet_AppendU16(&packet, in->operandB.size);
        TPM2_Packet_AppendBytes(&packet, in->operandB.buffer, in->operandB.size);

        TPM2_Packet_AppendU16(&packet, in->offset);
        TPM2_Packet_AppendU16(&packet, in->operation);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_PolicyCounterTimer);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PolicyCommandCode(PolicyCommandCode_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->policySession);

        TPM2_Packet_AppendU32(&packet, in->code);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_PolicyCommandCode);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PolicyCpHash(PolicyCpHash_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->policySession);

        TPM2_Packet_AppendU16(&packet, in->cpHashA.size);
        TPM2_Packet_AppendBytes(&packet, in->cpHashA.buffer, in->cpHashA.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_PolicyCpHash);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PolicyNameHash(PolicyNameHash_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->policySession);

        TPM2_Packet_AppendU16(&packet, in->nameHash.size);
        TPM2_Packet_AppendBytes(&packet, in->nameHash.buffer, in->nameHash.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_PolicyNameHash);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PolicyDuplicationSelect(PolicyDuplicationSelect_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->policySession);

        TPM2_Packet_AppendU16(&packet, in->objectName.size);
        TPM2_Packet_AppendBytes(&packet, in->objectName.name, in->objectName.size);

        TPM2_Packet_AppendU16(&packet, in->newParentName.size);
        TPM2_Packet_AppendBytes(&packet, in->newParentName.name, in->newParentName.size);

        TPM2_Packet_AppendU8(&packet, in->includeObject);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_PolicyDuplicationSelect);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PolicyAuthorize(PolicyAuthorize_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->policySession);

        TPM2_Packet_AppendU16(&packet, in->approvedPolicy.size);
        TPM2_Packet_AppendBytes(&packet, in->approvedPolicy.buffer, in->approvedPolicy.size);

        TPM2_Packet_AppendU16(&packet, in->policyRef.size);
        TPM2_Packet_AppendBytes(&packet, in->policyRef.buffer, in->policyRef.size);

        TPM2_Packet_AppendU16(&packet, in->keySign.size);
        TPM2_Packet_AppendBytes(&packet, in->keySign.name, in->keySign.size);

        TPM2_Packet_AppendU16(&packet, in->checkTicket.tag);
        TPM2_Packet_AppendU32(&packet, in->checkTicket.hierarchy);
        TPM2_Packet_AppendU16(&packet, in->checkTicket.digest.size);
        TPM2_Packet_AppendBytes(&packet,
                    in->checkTicket.digest.buffer,
                    in->checkTicket.digest.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_PolicyAuthorize);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}


static TPM_RC TPM2_PolicySessionOnly(TPM_CC cc, TPMI_SH_POLICY policy)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, policy);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, cc);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}


TPM_RC TPM2_PolicyPhysicalPresence(PolicyPhysicalPresence_In* in)
{
    return TPM2_PolicySessionOnly(TPM_CC_PolicyPhysicalPresence, in->policySession);
}

TPM_RC TPM2_PolicyAuthValue(PolicyAuthValue_In* in)
{
    return TPM2_PolicySessionOnly(TPM_CC_PolicyAuthValue, in->policySession);
}

TPM_RC TPM2_PolicyPassword(PolicyPassword_In* in)
{
    return TPM2_PolicySessionOnly(TPM_CC_PolicyPassword, in->policySession);
}

TPM_RC TPM2_PolicyGetDigest(PolicyGetDigest_In* in, PolicyGetDigest_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->policySession);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_PolicyGetDigest);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParseU16(&packet, &out->policyDigest.size);
            TPM2_Packet_ParseBytes(&packet, out->policyDigest.buffer, out->policyDigest.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PolicyNvWritten(PolicyNvWritten_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->policySession);
        TPM2_Packet_AppendU8(&packet, in->writtenSet);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_PolicyNvWritten);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PolicyTemplate(PolicyTemplate_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->policySession);
        TPM2_Packet_AppendU16(&packet, in->templateHash.size);
        TPM2_Packet_AppendBytes(&packet, in->templateHash.buffer, in->templateHash.size);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_PolicyTemplate);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PolicyAuthorizeNV(PolicyAuthorizeNV_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendU32(&packet, in->nvIndex);
        TPM2_Packet_AppendU32(&packet, in->policySession);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_PolicyAuthorizeNV);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}


TPM_RC TPM2_HierarchyControl(HierarchyControl_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendU32(&packet, in->enable);
        TPM2_Packet_AppendU8(&packet, in->state);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_HierarchyControl);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_SetPrimaryPolicy(SetPrimaryPolicy_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendU16(&packet, in->authPolicy.size);
        TPM2_Packet_AppendBytes(&packet, in->authPolicy.buffer, in->authPolicy.size);
        TPM2_Packet_AppendU16(&packet, in->hashAlg);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_SetPrimaryPolicy);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_ChangePPS(ChangePPS_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_ChangePPS);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_ChangeEPS(ChangeEPS_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_ChangeEPS);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_Clear(Clear_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_Clear);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_ClearControl(ClearControl_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->auth);
        TPM2_Packet_AppendU8(&packet, in->disable);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_ClearControl);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_HierarchyChangeAuth(HierarchyChangeAuth_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendU16(&packet, in->newAuth.size);
        TPM2_Packet_AppendBytes(&packet, in->newAuth.buffer, in->newAuth.size);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_HierarchyChangeAuth);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_DictionaryAttackLockReset(DictionaryAttackLockReset_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->lockHandle);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_DictionaryAttackLockReset);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_DictionaryAttackParameters(DictionaryAttackParameters_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->lockHandle);
        TPM2_Packet_AppendU32(&packet, in->newMaxTries);
        TPM2_Packet_AppendU32(&packet, in->newRecoveryTime);
        TPM2_Packet_AppendU32(&packet, in->lockoutRecovery);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_DictionaryAttackParameters);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_PP_Commands(PP_Commands_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        int i;
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->auth);

        TPM2_Packet_AppendU32(&packet, in->setList.count);
        for (i=0; i<(int)in->setList.count; i++) {
            TPM2_Packet_AppendU32(&packet, in->setList.commandCodes[i]);
        }
        TPM2_Packet_AppendU32(&packet, in->clearList.count);
        for (i=0; i<(int)in->clearList.count; i++) {
            TPM2_Packet_AppendU32(&packet, in->clearList.commandCodes[i]);
        }

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_PP_Commands);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_SetAlgorithmSet(SetAlgorithmSet_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendU32(&packet, in->algorithmSet);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_SetAlgorithmSet);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_FieldUpgradeStart(FieldUpgradeStart_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authorization);
        TPM2_Packet_AppendU32(&packet, in->keyHandle);

        TPM2_Packet_AppendU16(&packet, in->fuDigest.size);
        TPM2_Packet_AppendBytes(&packet, in->fuDigest.buffer, in->fuDigest.size);

        TPM2_Packet_AppendU16(&packet, in->manifestSignature.sigAlgo);
        TPM2_Packet_AppendU16(&packet, in->manifestSignature.signature.any.hashAlg);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_FieldUpgradeStart);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_FieldUpgradeData(FieldUpgradeData_In* in, FieldUpgradeData_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU16(&packet, in->fuData.size);
        TPM2_Packet_AppendBytes(&packet, in->fuData.buffer, in->fuData.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_FieldUpgradeData);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            int digestSz;
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParseU16(&packet, &out->nextDigest.hashAlg);
            digestSz = TPM2_GetHashDigestSize(out->nextDigest.hashAlg);
            TPM2_Packet_ParseBytes(&packet, out->nextDigest.digest.H, digestSz);

            TPM2_Packet_ParseU16(&packet, &out->firstDigest.hashAlg);
            digestSz = TPM2_GetHashDigestSize(out->firstDigest.hashAlg);
            TPM2_Packet_ParseBytes(&packet, out->firstDigest.digest.H, digestSz);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_FirmwareRead(FirmwareRead_In* in, FirmwareRead_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->sequenceNumber);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_FirmwareRead);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParseU16(&packet, &out->fuData.size);
            TPM2_Packet_ParseBytes(&packet, out->fuData.buffer, out->fuData.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_ContextSave(ContextSave_In* in, ContextSave_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->saveHandle);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_ContextSave);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParseU64(&packet, &out->context.sequence);
            TPM2_Packet_ParseU32(&packet, &out->context.savedHandle);
            TPM2_Packet_ParseU32(&packet, &out->context.hierarchy);

            TPM2_Packet_ParseU16(&packet, &out->context.contextBlob.size);
            TPM2_Packet_ParseBytes(&packet, out->context.contextBlob.buffer,
                out->context.contextBlob.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_ContextLoad(ContextLoad_In* in, ContextLoad_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU64(&packet, in->context.sequence);
        TPM2_Packet_AppendU32(&packet, in->context.savedHandle);
        TPM2_Packet_AppendU32(&packet, in->context.hierarchy);

        TPM2_Packet_AppendU16(&packet, in->context.contextBlob.size);
        TPM2_Packet_AppendBytes(&packet, in->context.contextBlob.buffer,
            in->context.contextBlob.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_ContextLoad);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParseU32(&packet, &out->loadedHandle);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_EvictControl(EvictControl_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->auth);
        TPM2_Packet_AppendU32(&packet, in->objectHandle);
        TPM2_Packet_AppendU32(&packet, in->persistentHandle);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_EvictControl);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_ReadClock(ReadClock_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_ReadClock);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParseU64(&packet, &out->currentTime.time);
            TPM2_Packet_ParseU64(&packet, &out->currentTime.clockInfo.clock);
            TPM2_Packet_ParseU32(&packet, &out->currentTime.clockInfo.resetCount);
            TPM2_Packet_ParseU32(&packet, &out->currentTime.clockInfo.restartCount);
            TPM2_Packet_ParseU8(&packet, &out->currentTime.clockInfo.safe);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_ClockSet(ClockSet_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->auth);
        TPM2_Packet_AppendU64(&packet, in->newTime);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_ClockSet);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_ClockRateAdjust(ClockRateAdjust_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU32(&packet, in->auth);
        TPM2_Packet_AppendU8(&packet, in->rateAdjust);
        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_ClockRateAdjust);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_TestParms(TestParms_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);
        TPM2_Packet_AppendU16(&packet, in->parameters.type);
        switch (in->parameters.type) {
            case TPM_ALG_KEYEDHASH:
                TPM2_Packet_AppendU16(&packet, in->parameters.parameters.keyedHashDetail.scheme.scheme);
                TPM2_Packet_AppendU16(&packet, in->parameters.parameters.keyedHashDetail.scheme.details.hmac.hashAlg);
                break;
            case TPM_ALG_SYMCIPHER:
                TPM2_Packet_AppendU16(&packet, in->parameters.parameters.symDetail.sym.algorithm);
                TPM2_Packet_AppendU16(&packet, in->parameters.parameters.symDetail.sym.keyBits.sym);
                TPM2_Packet_AppendU16(&packet, in->parameters.parameters.symDetail.sym.mode.sym);
                break;
            case TPM_ALG_RSA:
                TPM2_Packet_AppendU16(&packet, in->parameters.parameters.rsaDetail.symmetric.algorithm);
                TPM2_Packet_AppendU16(&packet, in->parameters.parameters.rsaDetail.symmetric.keyBits.sym);
                TPM2_Packet_AppendU16(&packet, in->parameters.parameters.rsaDetail.symmetric.mode.sym);

                TPM2_Packet_AppendU16(&packet, in->parameters.parameters.rsaDetail.scheme.scheme);
                TPM2_Packet_AppendU16(&packet, in->parameters.parameters.rsaDetail.scheme.details.anySig.hashAlg);

                TPM2_Packet_AppendU16(&packet, in->parameters.parameters.rsaDetail.keyBits);

                TPM2_Packet_AppendU32(&packet, in->parameters.parameters.rsaDetail.exponent);
                break;
            case TPM_ALG_ECC:
                TPM2_Packet_AppendU16(&packet, in->parameters.parameters.eccDetail.symmetric.algorithm);
                TPM2_Packet_AppendU16(&packet, in->parameters.parameters.eccDetail.symmetric.keyBits.sym);
                TPM2_Packet_AppendU16(&packet, in->parameters.parameters.eccDetail.symmetric.mode.sym);

                TPM2_Packet_AppendU16(&packet, in->parameters.parameters.eccDetail.scheme.scheme);
                TPM2_Packet_AppendU16(&packet, in->parameters.parameters.eccDetail.scheme.details.any.hashAlg);

                TPM2_Packet_AppendU16(&packet, in->parameters.parameters.eccDetail.curveID);

                TPM2_Packet_AppendU16(&packet, in->parameters.parameters.eccDetail.kdf.scheme);
                TPM2_Packet_AppendU16(&packet, in->parameters.parameters.eccDetail.kdf.details.any.hashAlg);
                break;
            default:
                TPM2_Packet_AppendU16(&packet, in->parameters.parameters.asymDetail.symmetric.algorithm);
                TPM2_Packet_AppendU16(&packet, in->parameters.parameters.asymDetail.symmetric.keyBits.sym);
                TPM2_Packet_AppendU16(&packet, in->parameters.parameters.asymDetail.symmetric.mode.sym);

                TPM2_Packet_AppendU16(&packet, in->parameters.parameters.asymDetail.scheme.scheme);
                TPM2_Packet_AppendU16(&packet, in->parameters.parameters.asymDetail.scheme.details.anySig.hashAlg);
                break;
        }

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_TestParms);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_NV_DefineSpace(NV_DefineSpace_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendU16(&packet, in->auth.size);
        TPM2_Packet_AppendBytes(&packet, in->auth.buffer, in->auth.size);

        TPM2_Packet_AppendU16(&packet, in->publicInfo.size);
        TPM2_Packet_AppendU32(&packet, in->publicInfo.nvPublic.nvIndex);
        TPM2_Packet_AppendU16(&packet, in->publicInfo.nvPublic.nameAlg);
        TPM2_Packet_AppendU32(&packet, in->publicInfo.nvPublic.attributes);

        TPM2_Packet_AppendU16(&packet, in->publicInfo.nvPublic.authPolicy.size);
        TPM2_Packet_AppendBytes(&packet, in->publicInfo.nvPublic.authPolicy.buffer,
            in->publicInfo.nvPublic.authPolicy.size);

        TPM2_Packet_AppendU16(&packet, in->publicInfo.nvPublic.dataSize);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_NV_DefineSpace);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_NV_UndefineSpace(NV_UndefineSpace_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendU32(&packet, in->nvIndex);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_NV_UndefineSpace);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_NV_UndefineSpaceSpecial(NV_UndefineSpaceSpecial_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->nvIndex);
        TPM2_Packet_AppendU32(&packet, in->platform);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_NV_UndefineSpaceSpecial);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_NV_ReadPublic(NV_ReadPublic_In* in, NV_ReadPublic_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->nvIndex);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_NV_ReadPublic);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParseU16(&packet, &out->nvPublic.size);
            TPM2_Packet_ParseU32(&packet, &out->nvPublic.nvPublic.nvIndex);
            TPM2_Packet_ParseU16(&packet, &out->nvPublic.nvPublic.nameAlg);
            TPM2_Packet_ParseU32(&packet, &out->nvPublic.nvPublic.attributes);

            TPM2_Packet_ParseU16(&packet, &out->nvPublic.nvPublic.authPolicy.size);
            TPM2_Packet_ParseBytes(&packet, out->nvPublic.nvPublic.authPolicy.buffer,
                out->nvPublic.nvPublic.authPolicy.size);

            TPM2_Packet_ParseU16(&packet, &out->nvPublic.nvPublic.dataSize);

            TPM2_Packet_ParseU16(&packet, &out->nvName.size);
            TPM2_Packet_ParseBytes(&packet, out->nvName.name, out->nvName.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_NV_Write(NV_Write_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendU32(&packet, in->nvIndex);

        TPM2_Packet_AppendU16(&packet, in->data.size);
        TPM2_Packet_AppendBytes(&packet, in->data.buffer, in->data.size);

        TPM2_Packet_AppendU16(&packet, in->offset);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_NV_Write);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_NV_Increment(NV_Increment_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendU32(&packet, in->nvIndex);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_NV_Increment);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_NV_Extend(NV_Extend_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendU32(&packet, in->nvIndex);

        TPM2_Packet_AppendU16(&packet, in->data.size);
        TPM2_Packet_AppendBytes(&packet, in->data.buffer, in->data.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_NV_Extend);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_NV_SetBits(NV_SetBits_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendU32(&packet, in->nvIndex);

        TPM2_Packet_AppendU64(&packet, in->bits);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_NV_SetBits);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_NV_WriteLock(NV_WriteLock_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendU32(&packet, in->nvIndex);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_NV_WriteLock);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_NV_GlobalWriteLock(NV_GlobalWriteLock_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authHandle);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_NV_GlobalWriteLock);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_NV_Read(NV_Read_In* in, NV_Read_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendU32(&packet, in->nvIndex);

        TPM2_Packet_AppendU16(&packet, in->size);
        TPM2_Packet_AppendU16(&packet, in->offset);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_NV_Read);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParseU16(&packet, &out->data.size);
            TPM2_Packet_ParseBytes(&packet, out->data.buffer, out->data.size);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_NV_ReadLock(NV_ReadLock_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendU32(&packet, in->nvIndex);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_NV_ReadLock);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_NV_ChangeAuth(NV_ChangeAuth_In* in)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->nvIndex);

        TPM2_Packet_AppendU16(&packet, in->newAuth.size);
        TPM2_Packet_AppendBytes(&packet, in->newAuth.buffer, in->newAuth.size);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_NV_ChangeAuth);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}

TPM_RC TPM2_NV_Certify(NV_Certify_In* in, NV_Certify_Out* out)
{
    TPM_RC rc;
    TPM2_CTX* ctx = TPM2_GetActiveCtx();

    if (ctx == NULL || in == NULL || out == NULL)
        return TPM_RC_BAD_ARG;

    rc = TPM2_AcquireLock(ctx);
    if (rc == TPM_RC_SUCCESS) {
        TPM2_Packet packet;
        TPM2_Packet_Init(ctx, &packet);

        TPM2_Packet_AppendU32(&packet, in->signHandle);
        TPM2_Packet_AppendU32(&packet, in->authHandle);
        TPM2_Packet_AppendU32(&packet, in->nvIndex);

        TPM2_Packet_AppendU16(&packet, in->qualifyingData.size);
        TPM2_Packet_AppendBytes(&packet, in->qualifyingData.buffer, in->qualifyingData.size);

        TPM2_Packet_AppendU16(&packet, in->inScheme.scheme);
        TPM2_Packet_AppendU16(&packet, in->inScheme.details.any.hashAlg);

        TPM2_Packet_AppendU16(&packet, in->size);
        TPM2_Packet_AppendU16(&packet, in->offset);

        TPM2_Packet_Finalize(&packet, TPM_ST_NO_SESSIONS, TPM_CC_NV_Certify);

        /* send command */
        rc = TPM2_SendCommand(ctx, &packet);
        if (rc == TPM_RC_SUCCESS) {
            rc = TPM2_Packet_Parse(rc, &packet);

            TPM2_Packet_ParseU16(&packet, &out->certifyInfo.size);
            TPM2_Packet_ParseBytes(&packet, out->certifyInfo.attestationData, out->certifyInfo.size);

            TPM2_Packet_ParseU16(&packet, &out->signature.sigAlgo);
            TPM2_Packet_ParseU16(&packet, &out->signature.signature.any.hashAlg);
        }

        TPM2_ReleaseLock(ctx);
    }
    return rc;
}



/* Utility functions not part of the specification */

int TPM2_GetHashDigestSize(TPMI_ALG_HASH hashAlg)
{
    switch (hashAlg) {
        case TPM_ALG_SHA1:
            return WC_SHA_DIGEST_SIZE;
        case TPM_ALG_SHA256:
            return WC_SHA256_DIGEST_SIZE;
        case TPM_ALG_SHA384:
            return WC_SHA384_DIGEST_SIZE;
        case TPM_ALG_SHA512:
            return WC_SHA512_DIGEST_SIZE;
        default:
            return 0;
    }
    return 0;
}

const char* TPM2_GetAlgName(TPM_ALG_ID alg)
{
    switch (alg) {
        case TPM_ALG_RSA:
            return "RSA";
        case TPM_ALG_SHA1:
            return "SHA1";
        case TPM_ALG_HMAC:
            return "HMAC";
        case TPM_ALG_AES:
            return "AES";
        case TPM_ALG_MGF1:
            return "MGF1";
        case TPM_ALG_KEYEDHASH:
            return "KEYEDHASH";
        case TPM_ALG_XOR:
            return "XOR";
        case TPM_ALG_SHA256:
            return "SHA256";
        case TPM_ALG_SHA384:
            return "SHA384";
        case TPM_ALG_SHA512:
            return "SHA512";
        case TPM_ALG_NULL:
            return "NULL";
        case TPM_ALG_SM3_256:
            return "SM3_256";
        case TPM_ALG_SM4:
            return "SM4";
        case TPM_ALG_RSASSA:
            return "RSASSA";
        case TPM_ALG_RSAES:
            return "RSAES";
        case TPM_ALG_RSAPSS:
            return "RSAPSS";
        case TPM_ALG_OAEP:
            return "OAEP";
        case TPM_ALG_ECDSA:
            return "ECDSA";
        case TPM_ALG_ECDH:
            return "ECDH";
        case TPM_ALG_ECDAA:
            return "ECDAA";
        case TPM_ALG_SM2:
            return "SM2";
        case TPM_ALG_ECSCHNORR:
            return "ECSCHNORR";
        case TPM_ALG_ECMQV:
            return "ECMQV";
        case TPM_ALG_KDF1_SP800_56A:
            return "KDF1_SP800_56A";
        case TPM_ALG_KDF2:
            return "KDF2";
        case TPM_ALG_KDF1_SP800_108:
            return "KDF1_SP800_108";
        case TPM_ALG_ECC:
            return "ECC";
        case TPM_ALG_SYMCIPHER:
            return "SYMCIPHER";
        case TPM_ALG_CTR:
            return "CTR";
        case TPM_ALG_OFB:
            return "OFB";
        case TPM_ALG_CBC:
            return "CBC";
        case TPM_ALG_CFB:
            return "CFB";
        case TPM_ALG_ECB:
            return "ECB";
        default:
            break;
    }
    return "Unknown";
}


const char* TPM2_GetRCString(TPM_RC rc)
{
    switch (rc) {
        case TPM_RC_SUCCESS:
            return "Success";
        case TPM_RC_BAD_TAG:
            return "Bad Tag";
        case TPM_RC_BAD_ARG:
            return "Bad Argument";
        case TPM_RC_INITIALIZE:
            return "TPM not initialized by TPM2_Startup or already initialized";
        case TPM_RC_FAILURE:
            return "Commands not being accepted because of a TPM failure";
        case TPM_RC_SEQUENCE:
            return "Improper use of a sequence handle";
        case TPM_RC_DISABLED:
            return "The command is disabled";
        case TPM_RC_EXCLUSIVE:
            return "Command failed because audit sequence required exclusivity";
        case TPM_RC_AUTH_TYPE:
            return "Authorization handle is not correct for command";
        case TPM_RC_AUTH_MISSING:
            return "Command requires an authorization session for handle and "
                "it is not present";
        case TPM_RC_POLICY:
            return "Policy failure in math operation or an invalid authPolicy "
                "value";
        case TPM_RC_PCR:
            return "PCR check fail";
        case TPM_RC_PCR_CHANGED:
            return "PCR have changed since checked";
        case TPM_RC_UPGRADE:
            return "Indicates that the TPM is in field upgrade mode";
        case TPM_RC_TOO_MANY_CONTEXTS:
            return "Context ID counter is at maximum";
        case TPM_RC_AUTH_UNAVAILABLE:
            return "The authValue or authPolicy is not available for selected "
                "entity";
        case TPM_RC_REBOOT:
            return "A _TPM_Init and Startup(CLEAR) is required before the TPM "
                "can resume operation";
        case TPM_RC_UNBALANCED:
            return "The protection algorithms (hash and symmetric) are not "
                "reasonably balanced";
        case TPM_RC_COMMAND_SIZE:
            return "Command commandSize value is inconsistent with contents of "
                "the command buffer";
        case TPM_RC_COMMAND_CODE:
            return "Command code not supported";
        case TPM_RC_AUTHSIZE:
            return "The value of authorizationSize is out of range or the "
                "number of octets in the Authorization Area is greater than "
                "required";
        case TPM_RC_AUTH_CONTEXT:
            return "Use of an authorization session with a context command or "
                "another command that cannot have an authorization session";
        case TPM_RC_NV_RANGE:
            return "NV offset+size is out of range";
        case TPM_RC_NV_SIZE:
            return "Requested allocation size is larger than allowed";
        case TPM_RC_NV_LOCKED:
            return "NV access locked";
        case TPM_RC_NV_AUTHORIZATION:
            return "NV access authorization fails in command actions";
        case TPM_RC_NV_UNINITIALIZED:
            return "An NV Index is used before being initialized or the state "
                "saved by TPM2_Shutdown(STATE) could not be restored";
        case TPM_RC_NV_SPACE:
            return "Insufficient space for NV allocation";
        case TPM_RC_NV_DEFINED:
            return "NV Index or persistent object already defined";
        case TPM_RC_BAD_CONTEXT:
            return "Context in TPM2_ContextLoad() is not valid";
        case TPM_RC_CPHASH:
            return "The cpHash value already set or not correct for use";
        case TPM_RC_PARENT:
            return "Handle for parent is not a valid parent";
        case TPM_RC_NEEDS_TEST:
            return "Some function needs testing";
        case TPM_RC_NO_RESULT:
            return "Cannot process a request due to an unspecified problem";
        case TPM_RC_SENSITIVE:
            return "The sensitive area did not unmarshal correctly after "
                "decryption";
        case TPM_RC_ASYMMETRIC:
            return "Asymmetric algorithm not supported or not correct";
        case TPM_RC_ATTRIBUTES:
            return "Inconsistent attributes";
        case TPM_RC_HASH:
            return "Hash algorithm not supported or not appropriate";
        case TPM_RC_VALUE:
            return "Value is out of range or is not correct for the context";
        case TPM_RC_HIERARCHY:
            return "Hierarchy is not enabled or is not correct for the use";
        case TPM_RC_KEY_SIZE:
            return "Key size is not supported";
        case TPM_RC_MGF:
            return "Mask generation function not supported";
        case TPM_RC_MODE:
            return "Mode of operation not supported";
        case TPM_RC_TYPE:
            return "The type of the value is not appropriate for the use";
        case TPM_RC_HANDLE:
            return "The handle is not correct for the use";
        case TPM_RC_KDF:
            return "Unsupported key derivation function or function not "
                "appropriate for use";
        case TPM_RC_RANGE:
            return "Value was out of allowed range";
        case TPM_RC_AUTH_FAIL:
            return "The authorization HMAC check failed and DA counter "
                "incremented";
        case TPM_RC_NONCE:
            return "Invalid nonce size or nonce value mismatch";
        case TPM_RC_PP:
            return "Authorization requires assertion of PP";
        case TPM_RC_SCHEME:
            return "Unsupported or incompatible scheme";
        case TPM_RC_SIZE:
            return "Structure is the wrong size";
        case TPM_RC_SYMMETRIC:
            return "Unsupported symmetric algorithm or key size, or not "
                "appropriate for instance";
        case TPM_RC_TAG:
            return "Incorrect structure tag";
        case TPM_RC_SELECTOR:
            return "Union selector is incorrect";
        case TPM_RC_INSUFFICIENT:
            return "The TPM was unable to unmarshal a value because there were "
                "not enough octets in the input buffer";
        case TPM_RC_SIGNATURE:
            return "The signature is not valid";
        case TPM_RC_KEY:
            return "Key fields are not compatible with the selected use";
        case TPM_RC_POLICY_FAIL:
            return "A policy check failed";
        case TPM_RC_INTEGRITY:
            return "Integrity check failed";
        case TPM_RC_TICKET:
            return "Invalid ticket";
        case TPM_RC_RESERVED_BITS:
            return "Reserved bits not set to zero as required";
        case TPM_RC_BAD_AUTH:
            return "Authorization failure without DA implications";
        case TPM_RC_EXPIRED:
            return "The policy has expired";
        case TPM_RC_POLICY_CC:
            return "The commandCode in the policy is not the commandCode of "
                "the command or the command code in a policy command "
                "references a command that is not implemented";
        case TPM_RC_BINDING:
            return "Public and sensitive portions of an object are not "
                "cryptographically bound";
        case TPM_RC_CURVE:
            return "Curve not supported";
        case TPM_RC_ECC_POINT:
            return "Point is not on the required curve";
        case TPM_RC_CONTEXT_GAP:
            return "Gap for context ID is too large";
        case TPM_RC_OBJECT_MEMORY:
            return "Out of memory for object contexts";
        case TPM_RC_SESSION_MEMORY:
            return "Out of memory for session contexts";
        case TPM_RC_MEMORY:
            return "Out of shared object/session memory or need space for "
                "internal operations";
        case TPM_RC_SESSION_HANDLES:
            return "Out of session handles; a session must be flushed before "
                "a new session may be created";
        case TPM_RC_OBJECT_HANDLES:
            return "Out of object handles";
        case TPM_RC_LOCALITY:
            return "Bad locality";
        case TPM_RC_YIELDED:
            return "The TPM has suspended operation on the command";
        case TPM_RC_CANCELED:
            return "The command was canceled";
        case TPM_RC_TESTING:
            return "TPM is performing self-tests";
        case TPM_RC_NV_RATE:
            return "The TPM is rate-limiting accesses to prevent wearout of NV";
        case TPM_RC_LOCKOUT:
            return "Authorizations for objects subject to DA protection are not"
                " allowed at this time because the TPM is in DA lockout mode";
        case TPM_RC_RETRY:
            return "The TPM was not able to start the command";
        case TPM_RC_NV_UNAVAILABLE:
            return "The command may require writing of NV and NV is not current"
                " accessible";
        case TPM_RC_NOT_USED:
            return "This value is reserved and shall not be returned by the "
                "TPM";
        default:
            break;
    }
    return "Unknown";
}

void TPM2_SetupPCRSel(TPML_PCR_SELECTION* pcr, TPM_ALG_ID alg, int pcrIndex)
{
    if (pcr) {
        pcr->count = 1;
        pcr->pcrSelections[0].hash = alg;
        pcr->pcrSelections[0].sizeofSelect = PCR_SELECT_MIN;
        XMEMSET(pcr->pcrSelections[0].pcrSelect, 0, PCR_SELECT_MIN);
        pcr->pcrSelections[0].pcrSelect[pcrIndex >> 3] = (1 << (pcrIndex & 0x7));
    }
}


#endif /* WOLFSSL_TPM2 */
