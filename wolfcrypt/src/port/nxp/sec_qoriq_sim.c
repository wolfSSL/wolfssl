/* sec_qoriq_sim.c
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

/*
 * Simulated backend for the QorIQ SEC driver: a host-runnable model of the
 * job ring state machine, so the driver's descriptor assembly, submission,
 * completion, timeout, reset-escalation and status-decoding logic runs
 * under make check on any machine, with fault injection for the paths real
 * hardware cannot be asked to take on demand.
 *
 * The model is CPU-native end to end (it implements wc_SecQoriqRead/Write
 * itself and interprets descriptor words the driver wrote), so it runs the
 * same on little and big endian hosts. Data buffers keep the port's big
 * endian fixed-width conventions, which mp_read/to_unsigned_bin share.
 *
 * Descriptor execution uses wolfCrypt's own software crypto: AES CBC/CTR/
 * ECB, AES-GCM (including the engine's write-plaintext-then-check-ICV
 * decrypt behaviour), the MDHA hashes, RNG4 instantiation and generation,
 * and the RSA/modexp protocol descriptors. ECDSA/ECDH protocol jobs report
 * a DECO error unless a status is injected; modelling the PKHA's curve
 * arithmetic is out of scope.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_SEC_QORIQ) && defined(WOLFSSL_SEC_QORIQ_SIM)

#include <wolfssl/wolfcrypt/port/nxp/sec_qoriq.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/wolfmath.h>

/* Fake physical address ranges, both below 4 GB so 32-bit pointer mode
 * accepts them. Persistent allocations (rings) and per-job mappings bump
 * separately so a stale job address can never alias a ring. */
#define SIM_PHYS_ALLOC_BASE 0x08000000UL
#define SIM_PHYS_JOB_BASE   0x04000000UL

#define SIM_MAX_ALLOCS 8
#define SIM_MAX_JOBBUF (SEC_QORIQ_DESC_MAX_BUFS + 1)

/* A CCB-sourced status that is not an ICV failure, for injected faults. */
#define SIM_STATUS_CCB_ERR 0x20000004UL

typedef struct SimMapEnt {
    void*  virt;
    word64 phys;
    word32 sz;
} SimMapEnt;

/* Engine and injection state. */
static struct {
    /* controller registers */
    word32 scfgr;
    word32 jrStart;
    word32 rdsta;
    word32 rtmctl;
    word32 rtsdctl;
    word32 rtfrqmin;
    word32 rtfrqmax;
    /* job ring registers and internal indexes */
    word32 irbaLs;
    word32 orbaLs;
    word32 irs;
    word32 ors;
    word32 orsf;
    word32 inRd;
    word32 outWr;
    /* fault injection */
    word32 nextStatus;
    int    nextStatusSet;
    int    timeoutNext;
    int    stickJrReset;
    int    stickDmaReset;
    int    jrResetStuck;
    int    dmaResetStuck;
    int    rngFailNext;
    word32 lastEntDelay;
    byte   rngCounter;
} sim;

/* The register window handed to the driver; never stores live state, it
 * only anchors the base + offset arithmetic. */
static byte simRegsPage[SEC_QORIQ_SIZE];

static SimMapEnt simAllocs[SIM_MAX_ALLOCS];
static word32    simAllocPhysUsed = 0;
static SimMapEnt simJobBufs[SIM_MAX_JOBBUF];
static word32    simJobCnt = 0;
static word32    simJobPhysUsed = 0;

/******************************************************************************
  Fault injection API
  ****************************************************************************/

void wc_SecQoriqSimReset(void)
{
    XMEMSET(&sim, 0, sizeof(sim));
}

void wc_SecQoriqSimNextStatus(word32 status)
{
    sim.nextStatus = status;
    sim.nextStatusSet = 1;
}

void wc_SecQoriqSimTimeoutNext(void)
{
    sim.timeoutNext = 1;
}

void wc_SecQoriqSimStickJrReset(int stick)
{
    sim.stickJrReset = stick;
}

void wc_SecQoriqSimStickDmaReset(int stick)
{
    sim.stickDmaReset = stick;
}

void wc_SecQoriqSimRngFailNext(int n)
{
    sim.rngFailNext = n;
}

word32 wc_SecQoriqSimRngEntDelay(void)
{
    return sim.lastEntDelay;
}

/******************************************************************************
  Address registry
  ****************************************************************************/

static void* simPhysToVirt(word64 phys, word32 len)
{
    word32 i;

    for (i = 0; i < SIM_MAX_ALLOCS; i++) {
        if ((simAllocs[i].virt != NULL) && (phys >= simAllocs[i].phys) &&
                (phys + len <= simAllocs[i].phys + simAllocs[i].sz)) {
            return (byte*)simAllocs[i].virt + (phys - simAllocs[i].phys);
        }
    }
    for (i = 0; i < simJobCnt; i++) {
        if ((phys >= simJobBufs[i].phys) &&
                (phys + len <= simJobBufs[i].phys + simJobBufs[i].sz)) {
            return (byte*)simJobBufs[i].virt + (phys - simJobBufs[i].phys);
        }
    }

    return NULL;
}

/******************************************************************************
  Descriptor interpreter
  ****************************************************************************/

typedef struct SimJob {
    const byte* key;      word32 keySz;
    const byte* ctx;      word32 ctxSz;  word32 ctxOfst; int haveCtx;
    const byte* msg[SEC_QORIQ_DESC_MAX_BUFS];
    word32      msgSz[SEC_QORIQ_DESC_MAX_BUFS];
    int         msgCnt;
    const byte* iv;       word32 ivSz;
    const byte* aad;      word32 aadSz;
    const byte* icv;      word32 icvSz;
    byte* outMsg;         word32 outMsgSz;
    byte* outRng;         word32 outRngSz;
    byte* outCtx;         word32 outCtxSz;
    /* A job descriptor can carry several OPERATIONs (RNG instantiation runs
     * INIT then the secure-key generation); ops[0] selects the dispatch. */
    word32 ops[4];        int opCnt;
    word32 op;
} SimJob;

#ifndef NO_AES
/* One flat message buffer for the AES paths, which the driver only ever
 * feeds as a single chunk. */
static const byte* simSingleMsg(const SimJob* job, word32* szOut)
{
    if (job->msgCnt != 1) {
        return NULL;
    }
    *szOut = job->msgSz[0];
    return job->msg[0];
}

static word32 simAesRun(const SimJob* job)
{
    Aes    aes;
    const byte* in;
    word32 inSz = 0;
    word32 aai = (job->op >> 4) & 0x1FF;
    int    enc = (int)(job->op & SEC_QORIQ_ENC);
    int    ret = NOT_COMPILED_IN;

    if (job->key == NULL || job->outMsg == NULL) {
        return SIM_STATUS_CCB_ERR;
    }
    in = simSingleMsg(job, &inSz);
    if (in == NULL || inSz != job->outMsgSz) {
        return SIM_STATUS_CCB_ERR;
    }

    if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) {
        return SIM_STATUS_CCB_ERR;
    }

    switch (aai) {
#ifdef HAVE_AES_CBC
        case 0x10: /* CBC */
            if (job->haveCtx && job->ctxSz >= WC_AES_BLOCK_SIZE) {
                ret = wc_AesSetKey(&aes, job->key, job->keySz, job->ctx,
                    enc ? AES_ENCRYPTION : AES_DECRYPTION);
                if (ret == 0) {
                    ret = enc ?
                        wc_AesCbcEncrypt(&aes, job->outMsg, in, inSz) :
                        wc_AesCbcDecrypt(&aes, job->outMsg, in, inSz);
                }
                /* Updated IV: last ciphertext block either way. */
                if (ret == 0 && job->outCtx != NULL &&
                        job->outCtxSz == WC_AES_BLOCK_SIZE &&
                        inSz >= WC_AES_BLOCK_SIZE) {
                    XMEMCPY(job->outCtx,
                        (enc ? job->outMsg : in) + inSz - WC_AES_BLOCK_SIZE,
                        WC_AES_BLOCK_SIZE);
                }
            }
            break;
#endif
#ifdef WOLFSSL_AES_COUNTER
        case 0x00: /* CTR */
            if (job->haveCtx && job->ctxOfst == 16 &&
                    job->ctxSz >= WC_AES_BLOCK_SIZE) {
                ret = wc_AesSetKey(&aes, job->key, job->keySz, job->ctx,
                    AES_ENCRYPTION);
                if (ret == 0) {
                    ret = wc_AesCtrEncrypt(&aes, job->outMsg, in, inSz);
                }
                if (ret == 0 && job->outCtx != NULL &&
                        job->outCtxSz == WC_AES_BLOCK_SIZE) {
                    XMEMCPY(job->outCtx, aes.reg, WC_AES_BLOCK_SIZE);
                }
            }
            break;
#endif
#ifdef HAVE_AES_ECB
        case 0x20: /* ECB */
            ret = wc_AesSetKey(&aes, job->key, job->keySz, NULL,
                enc ? AES_ENCRYPTION : AES_DECRYPTION);
            if (ret == 0) {
                ret = enc ?
                    wc_AesEcbEncrypt(&aes, job->outMsg, in, inSz) :
                    wc_AesEcbDecrypt(&aes, job->outMsg, in, inSz);
            }
            break;
#endif
        default:
            break;
    }

    wc_AesFree(&aes);
    return (ret == 0) ? 0 : SIM_STATUS_CCB_ERR;
}

#ifdef HAVE_AESGCM
static word32 simGcmRun(const SimJob* job)
{
    Aes    aes;
    const byte* in = NULL;
    word32 inSz = 0;
    byte   scratchTag[SEC_QORIQ_GCM_TAG_SZ];
    int    enc = (int)(job->op & SEC_QORIQ_ENC);
    int    ret;

    if (job->key == NULL || job->iv == NULL ||
            job->ivSz != SEC_QORIQ_GCM_IV_SZ) {
        return SIM_STATUS_CCB_ERR;
    }
    if (job->msgCnt > 1) {
        return SIM_STATUS_CCB_ERR;
    }
    if (job->msgCnt == 1) {
        in = job->msg[0];
        inSz = job->msgSz[0];
        if (job->outMsg == NULL || job->outMsgSz != inSz) {
            return SIM_STATUS_CCB_ERR;
        }
    }

    if (wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) {
        return SIM_STATUS_CCB_ERR;
    }
    ret = wc_AesGcmSetKey(&aes, job->key, job->keySz);

    if (ret == 0 && enc) {
        if (job->outCtx == NULL || job->outCtxSz != SEC_QORIQ_GCM_TAG_SZ) {
            ret = BAD_FUNC_ARG;
        }
        else {
            ret = wc_AesGcmEncrypt(&aes, job->outMsg, in, inSz, job->iv,
                job->ivSz, job->outCtx, SEC_QORIQ_GCM_TAG_SZ, job->aad,
                job->aadSz);
        }
    }
    else if (ret == 0) {
        if (job->icv == NULL || job->icvSz != SEC_QORIQ_GCM_TAG_SZ) {
            ret = BAD_FUNC_ARG;
        }
        else {
            ret = wc_AesGcmDecrypt(&aes, job->outMsg, in, inSz, job->iv,
                job->ivSz, job->icv, job->icvSz, job->aad, job->aadSz);
            if (ret == WC_NO_ERR_TRACE(AES_GCM_AUTH_E)) {
                /* The engine writes the plaintext before it compares the
                 * ICV. GCM's keystream is direction independent, so
                 * "encrypting" the ciphertext reproduces exactly what the
                 * engine leaves in the output buffer. */
                if (inSz > 0) {
                    (void)wc_AesGcmEncrypt(&aes, job->outMsg, in, inSz,
                        job->iv, job->ivSz, scratchTag,
                        SEC_QORIQ_GCM_TAG_SZ, job->aad, job->aadSz);
                }
                wc_AesFree(&aes);
                return SEC_QORIQ_SSRC_CCB << SEC_QORIQ_SSRC_SHIFT |
                       SEC_QORIQ_CCBERR_ERRID_ICV;
            }
        }
    }

    wc_AesFree(&aes);
    return (ret == 0) ? 0 : SIM_STATUS_CCB_ERR;
}
#endif /* HAVE_AESGCM */
#endif /* !NO_AES */

static word32 simHashRun(const SimJob* job)
{
    wc_HashAlg alg;
    enum wc_HashType type;
    byte digest[WC_MAX_DIGEST_SIZE];
    word32 digestSz;
    int i;
    int ret;

    switch ((job->op >> 16) & 0xFF) {
        case 0x40: type = WC_HASH_TYPE_MD5;    break;
        case 0x41: type = WC_HASH_TYPE_SHA;    break;
        case 0x42: type = WC_HASH_TYPE_SHA224; break;
        case 0x43: type = WC_HASH_TYPE_SHA256; break;
        case 0x44: type = WC_HASH_TYPE_SHA384; break;
        case 0x45: type = WC_HASH_TYPE_SHA512; break;
        default:   return SIM_STATUS_CCB_ERR;
    }

    ret = wc_HashGetDigestSize(type);
    if (ret <= 0) {
        return SIM_STATUS_CCB_ERR;
    }
    digestSz = (word32)ret;

    if (job->outCtx == NULL || job->outCtxSz != digestSz) {
        return SIM_STATUS_CCB_ERR;
    }

    ret = wc_HashInit(&alg, type);
    for (i = 0; (ret == 0) && (i < job->msgCnt); i++) {
        ret = wc_HashUpdate(&alg, type, job->msg[i], job->msgSz[i]);
    }
    if (ret == 0) {
        ret = wc_HashFinal(&alg, type, digest);
    }
    (void)wc_HashFree(&alg, type);

    if (ret != 0) {
        return SIM_STATUS_CCB_ERR;
    }
    XMEMCPY(job->outCtx, digest, digestSz);
    return 0;
}

static word32 simRngOne(const SimJob* job, word32 op)
{
    word32 i;

    if (op & SEC_QORIQ_RNG4_SK) {
        /* secure key generation: nothing observable to model */
        return 0;
    }
    if (op & SEC_QORIQ_ALG_INIT) {
        if (sim.rngFailNext > 0) {
            sim.rngFailNext--;
            return SIM_STATUS_CCB_ERR;
        }
        sim.rdsta |= SEC_QORIQ_RDSTA_IF0;
        return 0;
    }

    /* data generation */
    if ((sim.rdsta & SEC_QORIQ_RDSTA_IF0) == 0) {
        return SIM_STATUS_CCB_ERR; /* no state handle */
    }
    if (job->outRng == NULL) {
        return SIM_STATUS_CCB_ERR;
    }
    for (i = 0; i < job->outRngSz; i++) {
        job->outRng[i] = sim.rngCounter++;
    }
    return 0;
}

/* Run every RNG OPERATION in descriptor order, stopping at a failure the
 * way the engine's error halt does. */
static word32 simRngRun(const SimJob* job)
{
    word32 status = 0;
    int i;

    for (i = 0; (status == 0) && (i < job->opCnt); i++) {
        status = simRngOne(job, job->ops[i]);
    }
    return status;
}

#ifdef WOLFSSL_SEC_QORIQ_RSA
/* RSA protocol descriptors, executed with wolfCrypt's own big number code.
 * PDB layouts follow sec_qoriq_pkha.c:
 *   RSA public  {e|n, f(in), g(out), n, e, f_len}
 *   RSA private {d|n, g(in), f(out), n, d}
 */
static word32 simModExpRun(const word32* desc, word32 startIdx, int isPub)
{
    mp_int base, e, n, r;
    const byte* inV;
    const byte* nV;
    const byte* eV;
    byte* outV;
    word32 pdb0 = desc[1];
    word32 expSz = (pdb0 >> SEC_QORIQ_RSA_PDB_E_SHIFT) &
        SEC_QORIQ_RSA_PDB_LEN_MASK;
    word32 nSz = pdb0 & SEC_QORIQ_RSA_PDB_LEN_MASK;
    word32 inSz;
    int ret;

    if (startIdx < (word32)(isPub ? 6 : 5)) {
        return SIM_STATUS_CCB_ERR;
    }
    inSz = isPub ? desc[6] : nSz;

    inV  = (const byte*)simPhysToVirt(desc[2], inSz);
    outV = (byte*)simPhysToVirt(desc[3], nSz);
    nV   = (const byte*)simPhysToVirt(desc[4], nSz);
    eV   = (const byte*)simPhysToVirt(desc[5], expSz);
    if (inV == NULL || outV == NULL || nV == NULL || eV == NULL) {
        return SIM_STATUS_CCB_ERR;
    }

    if (mp_init_multi(&base, &e, &n, &r, NULL, NULL) != MP_OKAY) {
        return SIM_STATUS_CCB_ERR;
    }

    ret = mp_read_unsigned_bin(&base, inV, inSz);
    if (ret == 0) {
        ret = mp_read_unsigned_bin(&e, eV, expSz);
    }
    if (ret == 0) {
        ret = mp_read_unsigned_bin(&n, nV, nSz);
    }
    if (ret == 0) {
        ret = mp_exptmod(&base, &e, &n, &r);
    }
    if (ret == 0) {
        ret = mp_to_unsigned_bin_len(&r, outV, (int)nSz);
    }

    mp_forcezero(&base);
    mp_forcezero(&e);
    mp_clear(&n);
    mp_forcezero(&r);

    return (ret == 0) ? 0 : SIM_STATUS_CCB_ERR;
}
#endif /* WOLFSSL_SEC_QORIQ_RSA */

/* Execute one descriptor and return its raw job status word. */
static word32 simRunDesc(const word32* desc)
{
    SimJob job;
    word32 len      = desc[0] & 0x7F;
    word32 startIdx = (desc[0] >> 16) & 0x7F;
    word32 i;

    if (len < 2 || len > SEC_QORIQ_DESC_MAX_WORDS || startIdx >= len) {
        return SIM_STATUS_CCB_ERR;
    }

    /* Protocol descriptor: a PDB precedes the OPERATION at startIdx. */
    if (startIdx > 1) {
        word32 op = desc[startIdx];
        word32 proto = op & 0x00FF0000;

        switch (proto) {
#ifdef WOLFSSL_SEC_QORIQ_RSA
            case SEC_QORIQ_RSA_ENCRYPT:
                return simModExpRun(desc, startIdx, 1);
            case SEC_QORIQ_RSA_DECRYPT:
                return simModExpRun(desc, startIdx, 0);
#endif
            default:
                /* PKHA curve arithmetic is not modelled: report the DECO
                 * "invalid protocol" error the real parts use. */
                return (SEC_QORIQ_SSRC_DECO << SEC_QORIQ_SSRC_SHIFT) | 0x82;
        }
    }

    XMEMSET(&job, 0, sizeof(job));

    for (i = 1; i < len; i++) {
        word32 w = desc[i];
        word32 ctype = w >> 27;

        switch (ctype) {
            case 0x00: /* KEY */
                job.keySz = w & 0x3FF;
                job.key = (const byte*)simPhysToVirt(desc[++i], job.keySz);
                if (job.key == NULL) {
                    return SIM_STATUS_CCB_ERR;
                }
                break;

            case 0x02: /* LOAD */
                if (w & 0x00200000) { /* context load, pointer follows */
                    job.ctxSz   = w & 0xFF;
                    job.ctxOfst = (w >> 8) & 0xFF;
                    job.ctx = (const byte*)simPhysToVirt(desc[++i],
                        job.ctxSz);
                    if (job.ctx == NULL) {
                        return SIM_STATUS_CCB_ERR;
                    }
                    job.haveCtx = 1;
                }
                else {
                    /* immediate load (CLRW): data words follow inline */
                    i += ((w & 0xFF) + 3) / 4;
                }
                break;

            case 0x04: /* FIFO LOAD */
            {
                word32 type = w & 0x00380000;
                word32 sz   = w & 0xFFFF;
                const byte* p = NULL;

                if (w & SEC_QORIQ_CMD_IMM) {
                    i += (sz + 3) / 4;
                    break;
                }
                p = (const byte*)simPhysToVirt(desc[++i], sz);
                if (p == NULL) {
                    return SIM_STATUS_CCB_ERR;
                }
                if (type == SEC_QORIQ_FIFOL_TYPE_IV) {
                    job.iv = p;  job.ivSz = sz;
                }
                else if (type == SEC_QORIQ_FIFOL_TYPE_AAD) {
                    job.aad = p; job.aadSz = sz;
                }
                else if (type == SEC_QORIQ_FIFOL_TYPE_ICV) {
                    job.icv = p; job.icvSz = sz;
                }
                else { /* message */
                    if (job.msgCnt >= SEC_QORIQ_DESC_MAX_BUFS) {
                        return SIM_STATUS_CCB_ERR;
                    }
                    job.msg[job.msgCnt] = p;
                    job.msgSz[job.msgCnt] = sz;
                    job.msgCnt++;
                }
                break;
            }

            case 0x0A: /* STORE (context) */
                job.outCtxSz = w & 0xFF;
                job.outCtx = (byte*)simPhysToVirt(desc[++i], job.outCtxSz);
                if (job.outCtx == NULL) {
                    return SIM_STATUS_CCB_ERR;
                }
                break;

            case 0x0C: /* FIFO STORE */
            {
                word32 type = w & 0x003C0000;
                word32 sz   = w & 0xFFFF;
                byte* p = (byte*)simPhysToVirt(desc[++i], sz);

                if (p == NULL) {
                    return SIM_STATUS_CCB_ERR;
                }
                if (type == (SEC_QORIQ_FIFOS_TYPE_RNG & 0x003C0000)) {
                    job.outRng = p;  job.outRngSz = sz;
                }
                else {
                    job.outMsg = p;  job.outMsgSz = sz;
                }
                break;
            }

            case 0x10: /* OPERATION */
                if (job.opCnt < 4) {
                    job.ops[job.opCnt++] = w;
                }
                break;

            case 0x14: /* JUMP */
                break;

            default:
                return SIM_STATUS_CCB_ERR;
        }
    }

    if (job.opCnt == 0) {
        return SIM_STATUS_CCB_ERR;
    }
    job.op = job.ops[0];

    switch (job.op & 0x00F00000) {
#ifndef NO_AES
        case 0x00100000: /* AESA */
#ifdef HAVE_AESGCM
            if (((job.op >> 4) & 0x1FF) == 0x90) {
                return simGcmRun(&job);
            }
#endif
            return simAesRun(&job);
#endif
        case 0x00400000: /* MDHA */
            return simHashRun(&job);
        case 0x00500000: /* RNG4 */
            return simRngRun(&job);
        default:
            return SIM_STATUS_CCB_ERR;
    }
}

/* Fetch the descriptor the driver just published and retire it. */
static void simProcessJob(void)
{
    word32* inRing;
    word32* outRing;
    word32  descPhys;
    word32* descVirt;
    word32  status;

    if (sim.timeoutNext) {
        /* The job vanishes into the engine: no completion is ever posted,
         * so the driver's poll loop must time out and reset. */
        sim.timeoutNext = 0;
        return;
    }

    inRing = (word32*)simPhysToVirt(sim.irbaLs, sim.irs *
        (word32)sizeof(word32));
    outRing = (word32*)simPhysToVirt(sim.orbaLs, sim.ors * 2 *
        (word32)sizeof(word32));
    if (inRing == NULL || outRing == NULL || sim.irs == 0 || sim.ors == 0) {
        return;
    }

    descPhys = inRing[sim.inRd];
    sim.inRd = (sim.inRd + 1) % sim.irs;

    if (sim.nextStatusSet) {
        sim.nextStatusSet = 0;
        status = sim.nextStatus;
    }
    else {
        /* Resolve the header word; the descriptor array behind it is
         * always SEC_QORIQ_DESC_MAX_WORDS wide in the driver. */
        descVirt = (word32*)simPhysToVirt(descPhys, (word32)sizeof(word32));
        status = (descVirt != NULL) ? simRunDesc(descVirt) :
            SIM_STATUS_CCB_ERR;
    }

    outRing[sim.outWr * 2]     = descPhys;
    outRing[sim.outWr * 2 + 1] = status;
    sim.outWr = (sim.outWr + 1) % sim.ors;
    sim.orsf = 1;
}

/******************************************************************************
  Register model
  ****************************************************************************/

word32 wc_SecQoriqRead(const byte* base, word32 off)
{
    word32 eff = (word32)(base - simRegsPage) + off;

    switch (eff) {
        case SEC_QORIQ_MCFGR:
            return sim.dmaResetStuck ? SEC_QORIQ_MCFGR_DMA_RESET : 0;
        case SEC_QORIQ_SCFGR:
            return sim.scfgr;
        case SEC_QORIQ_JRSTART:
            return sim.jrStart;
        case SEC_QORIQ_RDSTA:
            return sim.rdsta;
        case SEC_QORIQ_RTMCTL:
            return sim.rtmctl;
        case SEC_QORIQ_RTSDCTL:
            return sim.rtsdctl;
        case SEC_QORIQ_RTFRQMIN:
            return sim.rtfrqmin;
        case SEC_QORIQ_RTFRQMAX:
            return sim.rtfrqmax;
        case SEC_QORIQ_CCBVID:
            return 6UL << SEC_QORIQ_CCBVID_ERA_SHIFT;
        case SEC_QORIQ_CHANUM_MS:
            return (4UL << SEC_QORIQ_CHANUM_MS_JRNUM_SHIFT) |
                   (1UL << SEC_QORIQ_CHANUM_MS_DECONUM_SHIFT);
        case SEC_QORIQ_CHANUM_LS:
            return (1UL << SEC_QORIQ_CHA_AES_SHIFT) |
                   (1UL << SEC_QORIQ_CHA_MD_SHIFT) |
                   (1UL << SEC_QORIQ_CHA_RNG_SHIFT) |
                   (1UL << SEC_QORIQ_CHA_PK_SHIFT);
        case SEC_QORIQ_CHAVID_LS:
            return 4UL << SEC_QORIQ_CHA_RNG_SHIFT; /* RNG4 */
        default:
            break;
    }

    /* job ring 0 page */
    switch (eff - (word32)SEC_QORIQ_JR_OFFSET(0)) {
        case SEC_QORIQ_IRSA:
            return sim.irs != 0 ? sim.irs : SEC_QORIQ_RING_SIZE;
        case SEC_QORIQ_ORSF:
            return sim.orsf;
        case SEC_QORIQ_JRCR:
            return sim.jrResetStuck ? SEC_QORIQ_JRCR_RESET : 0;
        case SEC_QORIQ_JRINT:
            return 0;
        default:
            break;
    }

    return 0;
}

void wc_SecQoriqWrite(byte* base, word32 off, word32 val)
{
    word32 eff = (word32)(base - simRegsPage) + off;

    switch (eff) {
        case SEC_QORIQ_MCFGR:
            if (val & SEC_QORIQ_MCFGR_DMA_RESET) {
                /* completes instantly unless injected to stick; either way
                 * any job the engine still held is gone */
                sim.dmaResetStuck = sim.stickDmaReset;
            }
            return;
        case SEC_QORIQ_SCFGR:
            sim.scfgr = val;
            return;
        case SEC_QORIQ_JRSTART:
            sim.jrStart = val;
            return;
        case SEC_QORIQ_RTMCTL:
            sim.rtmctl = val;
            return;
        case SEC_QORIQ_RTSDCTL:
            sim.rtsdctl = val;
            sim.lastEntDelay = (val & SEC_QORIQ_RTSDCTL_ENT_DLY_MASK) >>
                SEC_QORIQ_RTSDCTL_ENT_DLY_SHIFT;
            return;
        case SEC_QORIQ_RTFRQMIN:
            sim.rtfrqmin = val;
            return;
        case SEC_QORIQ_RTFRQMAX:
            sim.rtfrqmax = val;
            return;
        default:
            break;
    }

    switch (eff - (word32)SEC_QORIQ_JR_OFFSET(0)) {
        case SEC_QORIQ_IRBA_MS:
        case SEC_QORIQ_ORBA_MS:
            return; /* 32-bit mode: upper halves are zero */
        case SEC_QORIQ_IRBA_LS:
            sim.irbaLs = val;
            return;
        case SEC_QORIQ_ORBA_LS:
            sim.orbaLs = val;
            return;
        case SEC_QORIQ_IRS:
            sim.irs = val;
            return;
        case SEC_QORIQ_ORS:
            sim.ors = val;
            return;
        case SEC_QORIQ_IRJA:
            simProcessJob();
            return;
        case SEC_QORIQ_ORJR:
            sim.orsf = 0;
            return;
        case SEC_QORIQ_JRCR:
            if (val & SEC_QORIQ_JRCR_RESET) {
                if (sim.stickJrReset) {
                    sim.jrResetStuck = 1;
                }
                else {
                    /* ring reset: engine restarts at slot 0, any pending
                     * (timed out) job is dropped */
                    sim.jrResetStuck = 0;
                    sim.orsf = 0;
                    sim.inRd = 0;
                    sim.outWr = 0;
                }
            }
            return;
        case SEC_QORIQ_JRINT:
            return; /* write-one-to-clear, nothing latched */
        default:
            break;
    }
}

/******************************************************************************
  Environment seam
  ****************************************************************************/

int wc_SecQoriqMapRegs(byte** regsOut)
{
    if (regsOut == NULL) {
        return BAD_FUNC_ARG;
    }
    *regsOut = simRegsPage;
    return 0;
}

void wc_SecQoriqUnmapRegs(byte* regs)
{
    (void)regs;
}

void* wc_SecQoriqDmaAlloc(word32 sz, word64* physOut)
{
    word32 i;
    void* ptr;

    if (physOut == NULL || sz == 0) {
        return NULL;
    }

    for (i = 0; i < SIM_MAX_ALLOCS; i++) {
        if (simAllocs[i].virt == NULL) {
            break;
        }
    }
    if (i == SIM_MAX_ALLOCS) {
        return NULL;
    }

    ptr = XMALLOC(sz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (ptr == NULL) {
        return NULL;
    }

    simAllocs[i].virt = ptr;
    simAllocs[i].phys = SIM_PHYS_ALLOC_BASE + simAllocPhysUsed;
    simAllocs[i].sz   = sz;
    simAllocPhysUsed += (sz + 63U) & ~63U;

    *physOut = simAllocs[i].phys;
    return ptr;
}

void wc_SecQoriqDmaFree(void* virt, word64 phys, word32 sz)
{
    word32 i;

    (void)phys;
    (void)sz;

    if (virt == NULL) {
        return;
    }
    for (i = 0; i < SIM_MAX_ALLOCS; i++) {
        if (simAllocs[i].virt == virt) {
            simAllocs[i].virt = NULL;
            break;
        }
    }
    XFREE(virt, NULL, DYNAMIC_TYPE_TMP_BUFFER);
}

word64 wc_SecQoriqVirtToPhysLen(void* virt, word32 len)
{
    word32 i;

    for (i = 0; i < SIM_MAX_ALLOCS; i++) {
        if ((simAllocs[i].virt != NULL) && (virt >= simAllocs[i].virt) &&
                ((byte*)virt + len <=
                    (byte*)simAllocs[i].virt + simAllocs[i].sz)) {
            return simAllocs[i].phys +
                (word64)((byte*)virt - (byte*)simAllocs[i].virt);
        }
    }
    return 0;
}

int wc_SecQoriqDmaJobBegin(void)
{
    simJobCnt = 0;
    simJobPhysUsed = 0;
    return 0;
}

word64 wc_SecQoriqDmaMapBuf(void* virt, word32 sz, int dir)
{
    word64 phys;

    (void)dir;

    if (virt == NULL || sz == 0 || simJobCnt >= SIM_MAX_JOBBUF) {
        return 0;
    }

    phys = SIM_PHYS_JOB_BASE + simJobPhysUsed;
    simJobBufs[simJobCnt].virt = virt;
    simJobBufs[simJobCnt].phys = phys;
    simJobBufs[simJobCnt].sz   = sz;
    simJobCnt++;
    simJobPhysUsed += (sz + 63U) & ~63U;

    return phys;
}

void wc_SecQoriqDmaJobEnd(int ok, int abandoned)
{
    (void)ok;
    (void)abandoned;
    simJobCnt = 0;
    simJobPhysUsed = 0;
}

int wc_SecQoriqCacheFlush(void* virt, word32 sz)
{
    (void)sz;
    return (virt == NULL) ? BAD_FUNC_ARG : 0;
}

int wc_SecQoriqCacheInval(void* virt, word32 sz)
{
    (void)sz;
    return (virt == NULL) ? BAD_FUNC_ARG : 0;
}

void wc_SecQoriqCpuRelax(void)
{
}

int wc_SecQoriqGetSvr(word32* svrOut)
{
    if (svrOut == NULL) {
        return BAD_FUNC_ARG;
    }
    *svrOut = SEC_QORIQ_SVR_E_BIT;
    return 0;
}

#endif /* WOLFSSL_SEC_QORIQ && WOLFSSL_SEC_QORIQ_SIM */
