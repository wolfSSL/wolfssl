/* sec_qoriq.h
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
 * NXP QorIQ SEC (CAAM) hardware crypto engine, as fitted to the T-series
 * PowerPC parts. Verified on T2080 (SEC 5.2) and T1040 (SEC 5.0): both
 * report era 6 in CCBVID (their device trees claim 5), both place the SEC at
 * CCSR + 0x300000 with four job rings, and both declare "fsl,sec-v4.0", so
 * one descriptor format covers them.
 *
 * The SEC is only fitted on security-enabled ("E") part numbers.
 * wc_SecQoriqInit() checks SVR bit 0x80000 at run time.
 */

#ifndef WOLF_CRYPT_SEC_QORIQ_H
#define WOLF_CRYPT_SEC_QORIQ_H

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>

#ifdef WOLFSSL_SEC_QORIQ

/* Only the MMIO accessors byte swap, so a little endian host would get
 * correct registers but wrongly ordered descriptors. Refuse rather than
 * produce silently wrong crypto. */
#ifdef WOLFSSL_SEC_QORIQ_SWAP_REGS
    #error "WOLFSSL_SEC_QORIQ_SWAP_REGS is incomplete: descriptor and ring words are not swapped"
#endif

#ifdef __cplusplus
    extern "C" {
#endif

/* Driver-internal API, not part of wolfSSL's public surface. The simulated
 * backend exports it so the in-tree tests (a separate binary linking the
 * shared library) can drive the driver and the fault injection directly. */
#ifdef WOLFSSL_SEC_QORIQ_SIM
    #define WOLFSSL_SECQ_API WOLFSSL_API
#else
    #define WOLFSSL_SECQ_API WOLFSSL_LOCAL
#endif

/******************************************************************************
  Build configuration
  ****************************************************************************/

/* devId selecting the SEC through the crypto callback layer. Avoids values
 * other ports claim: 7 (CAAM), 8 (SECO/ARIA), 9 (MAX3266X), 807-810 (STM32
 * SAES/DHUK, RealTek HUK). */
#ifndef WOLFSSL_SEC_QORIQ_DEVID
    #define WOLFSSL_SEC_QORIQ_DEVID 0x53454351 /* "SECQ" */
#endif


/* Physical base of the CCSR window, which is board specific: the CW VPX3-152
 * U-Boot relocates it to 0xEF000000, the NXP RDBs default to 0xFE000000. */
#ifndef SEC_QORIQ_CCSRBAR
    #define SEC_QORIQ_CCSRBAR 0xFE000000UL
#endif

/* The same window as the operating system sees it. Bare metal runs with the
 * 32-bit view above, but these parts have a 36-bit physical address space and
 * Linux uses the full address: CCSR on a T1040 is 0xF_FE000000, not
 * 0xFE000000. Mapping the 32-bit value there hits ordinary DRAM instead, so
 * the physical base is a separate 64-bit knob rather than a widened
 * SEC_QORIQ_CCSRBAR, which several boards already set from a linker or board
 * header as a 32-bit constant. Override per board, for example
 * -DSEC_QORIQ_CCSRBAR_PHYS=0xFFE000000ULL. */
#ifndef SEC_QORIQ_CCSRBAR_PHYS
    #define SEC_QORIQ_CCSRBAR_PHYS ((word64)(SEC_QORIQ_CCSRBAR))
#endif

/* Offset of the SEC block within CCSR, fixed on every QorIQ part seen. */
#ifndef SEC_QORIQ_OFFSET
    #define SEC_QORIQ_OFFSET  0x300000UL
#endif
#define SEC_QORIQ_SIZE        0x10000UL

/* Which of the four job rings to claim. */
#ifndef SEC_QORIQ_JR_INDEX
    #define SEC_QORIQ_JR_INDEX 0
#endif

/* Job ring pages start one page into the block, one 4 KB page each. */
#define SEC_QORIQ_JR_OFFSET(n) (0x1000UL + ((unsigned long)(n) * 0x1000UL))

/* Descriptors are submitted one at a time, so a short ring suffices. */
#ifndef SEC_QORIQ_RING_SIZE
    #define SEC_QORIQ_RING_SIZE 4
#endif

/* Poll limit for job completion; a hung ring must not wedge the caller. */
#ifndef SEC_QORIQ_POLL_MAX
    #define SEC_QORIQ_POLL_MAX 1000000
#endif

/* Below this size the fixed per-job cost (about 3.5 us on a 1.2 GHz T2080:
 * descriptor build, two cache flushes, ring write, MMIO kick, completion
 * poll) outweighs what the engine saves for algorithms with a fast software
 * path. Measured AES-CBC crossover is 64 to 256 bytes. GCM always wins on
 * the engine and ignores this; hashing is not routed at all. */
#ifndef SEC_QORIQ_MIN_OFFLOAD_SZ
    #define SEC_QORIQ_MIN_OFFLOAD_SZ 256
#endif

/* Largest transfer one command can describe; the extended length form is
 * not implemented, so anything bigger goes to software. */
#define SEC_QORIQ_MAX_XFER_SZ 0xFFFF

/* The only GCM IV length whose J0 construction the AESA implements. */
#define SEC_QORIQ_GCM_IV_SZ 12

/* Full-length tag only: the engine does the ICV comparison itself and will
 * not take a truncated tag. TLS always uses 16. */
#define SEC_QORIQ_GCM_TAG_SZ 16

/* Descriptors are capped at 64 words by the hardware. */
#define SEC_QORIQ_DESC_MAX_WORDS 64

/* Most data buffers one descriptor can reference. The largest consumer is
 * the single-shot hash: 30 message chunks plus the digest store. */
#define SEC_QORIQ_DESC_MAX_BUFS 32

/* Direction of a DMA buffer, from the engine's point of view. */
#define SEC_QORIQ_DIR_IN  0 /* engine reads it */
#define SEC_QORIQ_DIR_OUT 1 /* engine writes it */

/******************************************************************************
  Controller registers, relative to the start of the SEC block
  ****************************************************************************/

#define SEC_QORIQ_MCFGR      0x0004 /* master configuration */
#define SEC_QORIQ_SCFGR      0x000C /* security configuration */
/* Job ring LIODN registers, two words per ring. U-Boot programs these. */
#define SEC_QORIQ_JRLIODNR(n) (0x0010 + ((n) * 8))
#define SEC_QORIQ_JRSTART    0x005C /* job ring start (only gates when
                                     * SCFGR[VIRT_EN] is set) */
#define SEC_QORIQ_DECORSR    0x0094 /* DECO request source */
#define SEC_QORIQ_DECORR     0x009C /* DECO request */
#define SEC_QORIQ_DECO_AVAIL 0x0120 /* DECO availability */
#define SEC_QORIQ_DECO_RESET 0x0124 /* DECO reset */

/* DECORSR / DECORR bits, for direct DECO0 access. */
#define SEC_QORIQ_DECORSR_JR0    0x00000001
#define SEC_QORIQ_DECORSR_VALID  0x80000000
#define SEC_QORIQ_DECORR_RQD0    0x00000001 /* request DECO0 direct access */
#define SEC_QORIQ_DECORR_DEN0    0x00010000 /* DECO0 available */

/* MCFGR bits */
#define SEC_QORIQ_MCFGR_SWRESET   0x80000000
#define SEC_QORIQ_MCFGR_WDENABLE  0x40000000
#define SEC_QORIQ_MCFGR_WDFAIL    0x20000000
#define SEC_QORIQ_MCFGR_DMA_RESET 0x10000000
#define SEC_QORIQ_MCFGR_LONG_PTR  0x00010000 /* >32-bit descriptor pointers */

/* SCFGR bits */
#define SEC_QORIQ_SCFGR_VIRT_EN   0x00008000
#define SEC_QORIQ_SCFGR_RDBENABLE 0x00000400 /* faster RNG reads */

/* JRSTART bits, one per ring */
#define SEC_QORIQ_JRSTART_JR(n)   (1U << (n))

/* Identification and capability registers (the perfmon page, +0xF00-0xFFF) */
#define SEC_QORIQ_CTPR_MS    0x0FA8 /* compile time parameters, ms half */
#define SEC_QORIQ_CTPR_LS    0x0FAC
#define SEC_QORIQ_CSTA       0x0FD4 /* controller status */
#define SEC_QORIQ_RVID       0x0FE0 /* RTIC version */
#define SEC_QORIQ_CCBVID     0x0FE4 /* CCB version, carries the SEC era */
#define SEC_QORIQ_CHAVID_MS  0x0FE8 /* per-accelerator version */
#define SEC_QORIQ_CHAVID_LS  0x0FEC
#define SEC_QORIQ_CHANUM_MS  0x0FF0 /* per-accelerator instance counts */
#define SEC_QORIQ_CHANUM_LS  0x0FF4
#define SEC_QORIQ_CAAMVID_MS 0x0FF8
#define SEC_QORIQ_CAAMVID_LS 0x0FFC

/* CTPR_MS bits */
#define SEC_QORIQ_CTPR_MS_QI     0x02000000 /* QMan interface present */
#define SEC_QORIQ_CTPR_MS_PS     0x00020000 /* >32-bit pointers supported */
#define SEC_QORIQ_CTPR_MS_DPAA2  0x00002000

/* CCBVID: SEC era lives in the top byte */
#define SEC_QORIQ_CCBVID_ERA_MASK  0xFF000000
#define SEC_QORIQ_CCBVID_ERA_SHIFT 24

/* CHANUM_MS: instance counts */
#define SEC_QORIQ_CHANUM_MS_JRNUM_SHIFT   28 /* number of job rings */
#define SEC_QORIQ_CHANUM_MS_DECONUM_SHIFT 24 /* number of DECOs */

/* CHANUM_LS / CHAVID_LS share this nibble layout: CHANUM_LS gives the number
 * of instances of each accelerator, CHAVID_LS gives their version. */
#define SEC_QORIQ_CHA_AES_SHIFT   0
#define SEC_QORIQ_CHA_DES_SHIFT   4
#define SEC_QORIQ_CHA_ARC4_SHIFT  8
#define SEC_QORIQ_CHA_MD_SHIFT   12
#define SEC_QORIQ_CHA_RNG_SHIFT  16
#define SEC_QORIQ_CHA_SNOW_SHIFT 20
#define SEC_QORIQ_CHA_KAS_SHIFT  24
#define SEC_QORIQ_CHA_PK_SHIFT   28
#define SEC_QORIQ_CHA_MASK       0xF

/******************************************************************************
  RNG4 registers, relative to the start of the SEC block
  ****************************************************************************/

#define SEC_QORIQ_RTMCTL     0x0600 /* misc control */
#define SEC_QORIQ_RTSCMISC   0x0604
#define SEC_QORIQ_RTPKRRNG   0x0608
#define SEC_QORIQ_RTPKRMAX   0x060C
#define SEC_QORIQ_RTSDCTL    0x0610 /* seed control, carries entropy delay */
#define SEC_QORIQ_RTSBLIM    0x0614
#define SEC_QORIQ_RTFRQMIN   0x0618
#define SEC_QORIQ_RTFRQMAX   0x061C
#define SEC_QORIQ_RTSTATUS   0x063C
#define SEC_QORIQ_RDSTA      0x06C0 /* DRNG status */

/* RTMCTL bits */
#define SEC_QORIQ_RTMCTL_PRGM     0x00010000 /* 1 = program, 0 = run */
#define SEC_QORIQ_RTMCTL_ACC      0x00000020 /* TRNG access mode */
#define SEC_QORIQ_RTMCTL_RESET    0x00000040 /* reset TRNG to defaults */
#define SEC_QORIQ_RTMCTL_ERR      0x00001000
#define SEC_QORIQ_RTMCTL_ENT_VAL  0x00000400 /* entropy ready */

/* RDSTA bits. IF0 clear means state handle 0 is not instantiated, which is
 * how the boot loaders on both boards tested leave it. */
#define SEC_QORIQ_RDSTA_IF0       0x00000001
#define SEC_QORIQ_RDSTA_IF1       0x00000002
#define SEC_QORIQ_RDSTA_PR0       0x00000010
#define SEC_QORIQ_RDSTA_PR1       0x00000020
#define SEC_QORIQ_RDSTA_SKVN      0x40000000
#define SEC_QORIQ_RDSTA_SKVT      0x80000000

/* Entropy delay: system clocks per entropy sample, longer being better. The
 * floor matches mainline Linux and NXP U-Boot. A shorter window samples the
 * ring oscillator too briefly on some parts, leaving the TRNG self checks as
 * the only guard against a weakly seeded handle. */
#define SEC_QORIQ_RTSDCTL_ENT_DLY_SHIFT 16
#define SEC_QORIQ_RTSDCTL_ENT_DLY_MASK  0xFFFF0000
#ifndef SEC_QORIQ_RTSDCTL_ENT_DLY_MIN
    #define SEC_QORIQ_RTSDCTL_ENT_DLY_MIN 3200
#endif
#define SEC_QORIQ_RTSDCTL_ENT_DLY_MAX   12800
#define SEC_QORIQ_RTSDCTL_ENT_DLY_STEP  400

/******************************************************************************
  Job ring registers, relative to the start of a job ring page
  ****************************************************************************/

#define SEC_QORIQ_IRBA    0x0000 /* input ring base, 64-bit  */
#define SEC_QORIQ_IRBA_MS 0x0000
#define SEC_QORIQ_IRBA_LS 0x0004
#define SEC_QORIQ_IRS     0x000C /* input ring size */
#define SEC_QORIQ_IRSA    0x0014 /* input ring slots available */
#define SEC_QORIQ_IRJA    0x001C /* input ring jobs added */
#define SEC_QORIQ_ORBA    0x0020 /* output ring base, 64-bit */
#define SEC_QORIQ_ORBA_MS 0x0020
#define SEC_QORIQ_ORBA_LS 0x0024
#define SEC_QORIQ_ORS     0x002C /* output ring size */
#define SEC_QORIQ_ORJR    0x0034 /* output ring jobs removed */
#define SEC_QORIQ_ORSF    0x003C /* output ring slots full */
#define SEC_QORIQ_JRSTA   0x0044 /* job ring output status */
#define SEC_QORIQ_JRINT   0x004C /* job ring interrupt status */
#define SEC_QORIQ_JRCFG_HI 0x0050 /* job ring configuration, ms half */
#define SEC_QORIQ_JRCFG    0x0054 /* job ring configuration, ls half */
#define SEC_QORIQ_IRRI    0x005C /* input ring read index */
#define SEC_QORIQ_ORWI    0x0064 /* output ring write index */
#define SEC_QORIQ_JRCR    0x006C /* job ring command */

/* JRCR bits */
#define SEC_QORIQ_JRCR_RESET 0x00000001

/* JRINT bits: 0 = interrupt asserted, 1 = error, 3:2 = halt state. */
#define SEC_QORIQ_JRINT_JRI            0x00000001
#define SEC_QORIQ_JRINT_ERR            0x00000002
#define SEC_QORIQ_JRINT_HALT_MASK      0x0000000C
#define SEC_QORIQ_JRINT_HALT_INPROGRESS 0x00000004
#define SEC_QORIQ_JRINT_HALT_COMPLETE  0x00000008

/* Job status. The top nibble names what reported the failure, telling an
 * operation the engine ran and rejected (a failed authentication or
 * signature check) apart from one it could not run at all. */
#define SEC_QORIQ_SSRC_SHIFT   28
#define SEC_QORIQ_SSRC_MASK    0xF0000000U
#define SEC_QORIQ_SSRC_NONE    0x0
#define SEC_QORIQ_SSRC_CCB     0x2
#define SEC_QORIQ_SSRC_JUMP    0x3
#define SEC_QORIQ_SSRC_DECO    0x4
#define SEC_QORIQ_SSRC_QI      0x5
#define SEC_QORIQ_SSRC_JR      0x6
#define SEC_QORIQ_SSRC_JUMP_CC 0x7

/* For a CCB error the error id is the bottom nibble. */
#define SEC_QORIQ_CCBERR_ERRID_MASK  0x0000000FU
#define SEC_QORIQ_CCBERR_ERRID_ICV   0x0A

/******************************************************************************
  Descriptor commands, common to every SEC/CAAM era.
  ****************************************************************************/

#define SEC_QORIQ_CMD_HEAD      0xB0800000
#define SEC_QORIQ_CMD_KEY       0x00000000
#define SEC_QORIQ_CMD_LOAD      0x10000000
#define SEC_QORIQ_CMD_LOAD_CTX  0x10200000
#define SEC_QORIQ_CMD_IMM       0x00800000
#define SEC_QORIQ_CMD_FIFO_L    0x20000000
#define SEC_QORIQ_CMD_FIFO_S    0x60000000
#define SEC_QORIQ_CMD_STORE     0x50000000
#define SEC_QORIQ_CMD_STORE_CTX 0x50200000
#define SEC_QORIQ_CMD_MOVE      0x78000000
#define SEC_QORIQ_CMD_OP        0x80000000
#define SEC_QORIQ_CMD_JUMP      0xA0000000
#define SEC_QORIQ_CMD_SEQI      0xF0000000
#define SEC_QORIQ_CMD_SEQO      0xF8000000
#define SEC_QORIQ_CMD_NWB       0x00200000

/* Accelerator class selection */
#define SEC_QORIQ_CLASS1 0x02000000 /* AESA, PKHA */
#define SEC_QORIQ_CLASS2 0x04000000 /* MDHA */

/* OPERATION command state and direction */
#define SEC_QORIQ_ENC        0x00000001
#define SEC_QORIQ_DEC        0x00000000
#define SEC_QORIQ_ALG_UPDATE 0x00000000
#define SEC_QORIQ_ALG_ICV    0x00000002
#define SEC_QORIQ_ALG_INIT   0x00000004
#define SEC_QORIQ_ALG_FINAL  0x00000008
#define SEC_QORIQ_ALG_INITF  0x0000000C

/* AES algorithm identifiers */
#define SEC_QORIQ_AESCTR 0x00100000
#define SEC_QORIQ_AESCBC 0x00100100
#define SEC_QORIQ_AESECB 0x00100200
#define SEC_QORIQ_AESCFB 0x00100300
#define SEC_QORIQ_AESOFB 0x00100400
#define SEC_QORIQ_AESCMAC 0x00100600
#define SEC_QORIQ_AESCCM 0x00100800
#define SEC_QORIQ_AESGCM 0x00100900

/* Message digest algorithm identifiers */
#define SEC_QORIQ_MD5    0x00400000
#define SEC_QORIQ_SHA1   0x00410000
#define SEC_QORIQ_SHA224 0x00420000
#define SEC_QORIQ_SHA256 0x00430000
#define SEC_QORIQ_SHA384 0x00440000
#define SEC_QORIQ_SHA512 0x00450000

/* HMAC is the same identifier with the AAI field set to 0x10 */
#define SEC_QORIQ_HMAC_AAI 0x00000010

/* Context offset field used by LOAD/STORE CTX. CBC keeps its IV at offset 0
 * of the class 1 context; CTR's counter lives further in. */
#define SEC_QORIQ_CTX_OFST_CBC 0x00000000
#define SEC_QORIQ_CTX_OFST_CTR 0x00001000

/* Context sizes: the accelerator's full state width plus the 8 byte running
 * message length. The truncated variants share the context width of their
 * parent (SHA-224 with SHA-256, SHA-384 with SHA-512), so these do not follow
 * from the digest size. */
#define SEC_QORIQ_MD5_CTXSZ    (16 + 8)
#define SEC_QORIQ_SHA1_CTXSZ   (20 + 8)
#define SEC_QORIQ_SHA224_CTXSZ (32 + 8)
#define SEC_QORIQ_SHA256_CTXSZ (32 + 8)
#define SEC_QORIQ_SHA384_CTXSZ (64 + 8)
#define SEC_QORIQ_SHA512_CTXSZ (64 + 8)

/* RNG */
#define SEC_QORIQ_RNG     0x00500000
#define SEC_QORIQ_ENTROPY 0x00500001

/* RNG4 "generate secure keys" variant, used once during instantiation to
 * load the JDKEK, TDKEK and TDSK registers. */
#define SEC_QORIQ_RNG4_SK 0x00001000

/* Pieces of the instantiation descriptor. The JUMP waits for the class 1
 * accelerator to finish; the LOAD writes 1 to the CLRW register, which
 * clears the done interrupt and returns the RNG to idle. */
#define SEC_QORIQ_JUMP_CLASS1  0x02000000
#define SEC_QORIQ_LOAD_CLRW    0x10880004
#define SEC_QORIQ_CLRW_RESET   0x00000001

/* FIFO LOAD input types */
#define SEC_QORIQ_FIFOL_TYPE_MSG 0x00100000
#define SEC_QORIQ_FIFOL_TYPE_IV  0x00200000
#define SEC_QORIQ_FIFOL_TYPE_AAD 0x00300000
#define SEC_QORIQ_FIFOL_TYPE_ICV 0x00380000
#define SEC_QORIQ_FIFOL_TYPE_FC1 0x00010000
#define SEC_QORIQ_FIFOL_TYPE_LC1 0x00020000
#define SEC_QORIQ_FIFOL_TYPE_LC2 0x00040000

/* FIFO STORE output types */
#define SEC_QORIQ_FIFOS_TYPE_MSG 0x00300000
#define SEC_QORIQ_FIFOS_TYPE_RNG 0x00340000
#define SEC_QORIQ_FIFOS_EXT      0x00400000
#define SEC_QORIQ_FIFOS_CONT     0x00800000

/* PKHA operation identifiers */
#define SEC_QORIQ_PKHA_OP        0x01000000
#define SEC_QORIQ_ECDSA_KEYPAIR  0x00140000
#define SEC_QORIQ_ECDSA_SIGN     0x00150000
#define SEC_QORIQ_ECDSA_VERIFY   0x00160000
#define SEC_QORIQ_ECDSA_ECDH     0x00170000
#define SEC_QORIQ_RSA_ENCRYPT    0x00180000
#define SEC_QORIQ_RSA_DECRYPT    0x00190000

/* PKHA protocol descriptor fields. These sit in the OPERATION word beside
 * the operation identifier above. */
#define SEC_QORIQ_PROT_UNIDI 0x00000000
#define SEC_QORIQ_PKHA_ECC   0x00000002

/* First word of a PKHA protocol data block: field prime and group order
 * sizes, in bytes.
 *
 * Two shortcuts the i.MX CAAM parts offer are refused here, both established
 * by experiment on a T2080 (era 6, PKHA v2):
 *
 *  - Naming a built-in curve by index instead of supplying the domain
 *    parameters. Every flag position in bits 25:17 crossed with every curve
 *    index 0..31 returns DECO error 0x82, so this port always passes the
 *    parameters explicitly. It costs a few descriptor words and gains any
 *    prime curve wolfCrypt knows rather than the handful built in.
 *  - The "message representative is already hashed" PROTINFO flag, refused
 *    with DECO error 0x81. Leaving it clear works, and the engine then takes
 *    the representative as given, which is what wolfCrypt passes anyway. */
#define SEC_QORIQ_PKHA_PDB_L_SHIFT 7
#define SEC_QORIQ_PKHA_PDB_L_MASK  0x3FF
#define SEC_QORIQ_PKHA_PDB_N_MASK  0x7F

/* DECO error id reported when the engine ran a verify and the signature did
 * not check out. Distinct from a fault, so it must not be reported as one. */
#define SEC_QORIQ_DECOERR_SIGVERIFY 0x86

/******************************************************************************
  Types
  ****************************************************************************/

/* One data buffer a descriptor references. Recorded while the descriptor is
 * assembled; the address word is filled in at submission, when the platform
 * backend maps (or stages) the buffer for DMA. */
typedef struct SecQoriqDescBuf {
    void*  virt;
    word32 sz;
    word32 wordIdx; /* descriptor word that receives the DMA address */
    byte   dir;     /* SEC_QORIQ_DIR_IN or SEC_QORIQ_DIR_OUT */
} SecQoriqDescBuf;

/* A descriptor under construction; the header is patched on submit. */
typedef struct SecQoriqDesc {
    word32 desc[SEC_QORIQ_DESC_MAX_WORDS];
    word32 idx;      /* next free word */
    word32 startIdx; /* HEADER START INDEX: the word the engine begins
                      * executing at. 1 for a plain job descriptor, and the
                      * index of the OPERATION for a protocol descriptor,
                      * whose parameter block precedes it. */
    /* Buffers referenced by the words above, resolved at submission. */
    SecQoriqDescBuf bufs[SEC_QORIQ_DESC_MAX_BUFS];
    word32 bufCnt;
} SecQoriqDesc;

/* Everything the driver needs to talk to one job ring.
 *
 * Threading: a process-wide singleton. Job submission is serialised on the
 * wolfSSL hardware mutex inside wc_SecQoriqRun(); the rest is deliberately
 * weaker:
 *
 *  - lastStatus and the cb* counters are diagnostics, written under no lock.
 *    lastStatus belongs to whichever job finished last, not the caller's.
 *    The counters are incremented in the callback router, before the job
 *    ring mutex is taken, so concurrent callers lose updates: read them as
 *    approximate under multi-threaded use, exact when single-threaded.
 *  - The RNG4 programming sequence (status check, RTSDCTL entropy-delay
 *    writes, instantiation job) is not atomic, so wc_SecQoriqRngInit() runs
 *    exactly once, inside wc_SecQoriqInit() before the crypto callback is
 *    registered and before worker threads can reach the device. There is no
 *    lazy path: wc_SecQoriqRandomBlock() and wc_SecQoriqEccSign() only
 *    re-read RDSTA (a side-effect-free register read) in case another agent
 *    instantiated the handle later, and never program the TRNG.
 *  - wc_SecQoriqInit()/Free() take no lock and do not wait for in-flight
 *    work. Quiesce every user before tearing the device down, or the
 *    register window is unmapped under a running job. */
typedef struct SecQoriqDev {
    byte*  regs;      /* mapped base of the SEC block */
    byte*  jr;        /* mapped base of the claimed job ring page */
    word32 jrIndex;
    word32 era;
    word32 chaNumLs;  /* cached CHANUM_LS, for capability checks */
    word32 chaVidLs;  /* cached CHAVID_LS */

    /* Input ring: one descriptor pointer per entry. Output ring: two words,
     * the descriptor pointer then its status. word32 because the driver runs
     * the SEC in 32-bit pointer mode. */
    word32* inRing;
    word64  inRingPhys;
    word32* outRing;
    word64  outRingPhys;

    /* Mirrors of the engine's own head and tail, so submissions land on the
     * slot it is about to read and results come from the one it just wrote.
     * Getting this wrong does not fail loudly: the stale contents of slot 0
     * look like a completed job. */
    word32 inIdx;
    word32 outIdx;

    /* Raw status of the most recent job; the decoded error loses the source
     * and error-id fields. */
    word32 lastStatus;

    /* Diagnostics: how much work reached the engine, answering "is this
     * really being offloaded" without guessing from timings. */
    word32 jobCount;      /* descriptors actually submitted to the ring */
    word32 cbHashCount;   /* WC_ALGO_TYPE_HASH seen by the router */
    word32 cbHashOffload; /* ...of those, handed to the engine */
    word32 cbCipherCount;
    word32 cbCipherOffload;
    word32 cbPkCount;
    word32 cbPkOffload;
    word32 cbSeedCount;

    byte    initialized;
    byte    rngReady;  /* RDSTA[IF0] observed or successfully instantiated */
    byte    longPtr;   /* MCFGR[LONG_PTR], 0 means 32-bit descriptor pointers */
    byte    quiesceFailed; /* a hung job survived both the ring reset and the
                            * DMA reset: the engine may still hold physical
                            * addresses of ours, so nothing it can reach is
                            * ever freed or reused. wc_SecQoriqFree() then
                            * unregisters the callback but deliberately leaks
                            * the rings and mappings. */
} SecQoriqDev;

/******************************************************************************
  Core API
  ****************************************************************************/

/* Bring up the SEC and register the crypto callback under
 * WOLFSSL_SEC_QORIQ_DEVID. Returns 0 on success. */
WOLFSSL_API int wc_SecQoriqInit(void);

/* Tear down and unregister. */
WOLFSSL_API int wc_SecQoriqFree(void);

/* Raw register access. Exposed because the RNG4 programming sequence is not
 * expressible as a descriptor and has to touch registers directly. */
WOLFSSL_SECQ_API word32 wc_SecQoriqRead(const byte* base, word32 off);
WOLFSSL_SECQ_API void   wc_SecQoriqWrite(byte* base, word32 off, word32 val);

/* Accessor for the singleton device, NULL before wc_SecQoriqInit(). */
WOLFSSL_SECQ_API SecQoriqDev* wc_SecQoriqGetDev(void);

#if defined(WOLF_CRYPTO_CB) && !defined(WOLFSSL_SEC_QORIQ_NO_CRYPTOCB)
/* Called by wc_SecQoriqInit/Free; exposed so an application that manages
 * registration itself can do so. */
WOLFSSL_SECQ_API int  wc_SecQoriqRegisterCryptoCb(void);
WOLFSSL_SECQ_API void wc_SecQoriqUnregisterCryptoCb(void);
#endif

/* Descriptor assembly. Each returns 0 on success or a negative error.
 *
 * Buffers are recorded, not translated: the DMA address words are filled in
 * at submission by the platform's wc_SecQoriqDmaMapBuf(), so a backend that
 * must stage data through a pinned bounce arena (Linux) sees every buffer.
 * There is deliberately no way to append a raw physical address.
 *
 * wc_SecQoriqDescAddBuf() infers the direction from the command (FIFO STORE
 * and STORE are engine writes, everything else engine reads);
 * wc_SecQoriqDescAddPdbPtr() appends a bare PDB pointer word, whose command
 * carries no direction, so the caller states it. */
WOLFSSL_SECQ_API int wc_SecQoriqDescInit(SecQoriqDesc* desc);
WOLFSSL_SECQ_API int wc_SecQoriqDescAddWord(SecQoriqDesc* desc, word32 in);
WOLFSSL_SECQ_API int wc_SecQoriqDescAddBuf(SecQoriqDesc* desc, word32 cmd,
    const byte* buf, word32 bufSz);
WOLFSSL_SECQ_API int wc_SecQoriqDescAddPdbPtr(SecQoriqDesc* desc,
    const byte* buf, word32 bufSz, int isOut);

/* Submit a descriptor to the job ring and wait for it to retire.
 *
 * Error contract, which the crypto callback router relies on: BAD_FUNC_ARG,
 * BUFFER_E, MEMORY_E and NOT_COMPILED_IN are only ever raised before the
 * job is handed to the engine, so a caller may retry in software over the
 * same buffers. WC_HW_E can be raised after submission (a timeout, a job
 * the engine ran and faulted), when caller buffers and chaining state may
 * already have been modified, and must be treated as a hard error. */
WOLFSSL_SECQ_API int wc_SecQoriqRun(SecQoriqDev* dev, SecQoriqDesc* desc);

/* As wc_SecQoriqRun(), but also hands back the raw job status of this very
 * job, captured while the lock is still held. Callers that classify the
 * outcome must use this rather than SecQoriqDev.lastStatus, which belongs to
 * whichever job finished last and is not written on every failure path. */
WOLFSSL_SECQ_API int wc_SecQoriqRunEx(SecQoriqDev* dev, SecQoriqDesc* desc,
    word32* statusOut);

/* Decode a job ring status word into a wolfSSL error and, when logging is on,
 * a human readable reason. */
WOLFSSL_SECQ_API int wc_SecQoriqParseError(word32 status);

/******************************************************************************
  Message digests. Single shot only for now: one descriptor initialises,
  absorbs the message and finalises. Streaming needs the class 2 context
  round tripped around each call and is not implemented yet.

  The 64-word descriptor bounds the message at 30 FIFO loads: 29 full
  block-aligned chunks plus one final chunk of up to 64 KB, about 1.9 MB.
  Anything larger is refused with BAD_FUNC_ARG.
  ****************************************************************************/

WOLFSSL_SECQ_API int wc_SecQoriqHash(word32 algo, word32 digestSz,
    const byte* in, word32 inSz, byte* out);
WOLFSSL_SECQ_API int wc_SecQoriqSha1(const byte* in, word32 inSz, byte* out);
WOLFSSL_SECQ_API int wc_SecQoriqSha224(const byte* in, word32 inSz, byte* out);
WOLFSSL_SECQ_API int wc_SecQoriqSha256(const byte* in, word32 inSz, byte* out);
WOLFSSL_SECQ_API int wc_SecQoriqSha384(const byte* in, word32 inSz, byte* out);
WOLFSSL_SECQ_API int wc_SecQoriqSha512(const byte* in, word32 inSz, byte* out);

#ifndef NO_AES
/******************************************************************************
  AES, confidentiality-only modes. Input must be a whole number of blocks;
  the caller handles any partial trailing block for CTR. Where the mode has a
  chaining value, iv is updated in place.
  ****************************************************************************/

WOLFSSL_SECQ_API int wc_SecQoriqAes(word32 mode, int encrypt, const byte* key,
    word32 keySz, byte* iv, const byte* in, word32 inSz, byte* out);
WOLFSSL_SECQ_API int wc_SecQoriqAesCbcEncrypt(const byte* key, word32 keySz,
    byte* iv, const byte* in, word32 inSz, byte* out);
WOLFSSL_SECQ_API int wc_SecQoriqAesCbcDecrypt(const byte* key, word32 keySz,
    byte* iv, const byte* in, word32 inSz, byte* out);
WOLFSSL_SECQ_API int wc_SecQoriqAesCtrEncrypt(const byte* key, word32 keySz,
    byte* iv, const byte* in, word32 inSz, byte* out);
WOLFSSL_SECQ_API int wc_SecQoriqAesEcbEncrypt(const byte* key, word32 keySz,
    const byte* in, word32 inSz, byte* out);
WOLFSSL_SECQ_API int wc_SecQoriqAesEcbDecrypt(const byte* key, word32 keySz,
    const byte* in, word32 inSz, byte* out);
#endif /* !NO_AES */

#ifndef WC_NO_RNG
/******************************************************************************
  RNG4. The boot loaders on the boards tested leave state handle 0
  uninstantiated, so wc_SecQoriqInit() instantiates it itself.
  ****************************************************************************/

/* Program the TRNG and instantiate state handle 0. Called once from
 * wc_SecQoriqInit(), before the crypto callback is registered: the status
 * check and TRNG programming are not atomic, so this must not run
 * concurrently with itself or with other jobs. A failure is recorded
 * (rngReady stays 0) and hardware seeding is reported unavailable. */
WOLFSSL_SECQ_API int wc_SecQoriqRngInit(void);
WOLFSSL_SECQ_API int wc_SecQoriqRandomBlock(byte* out, word32 sz);
#endif /* !WC_NO_RNG */

#ifdef HAVE_AESGCM
/* GCM takes an arbitrary message length. On decrypt the engine checks the
 * tag itself and a mismatch comes back as AES_GCM_AUTH_E. */
WOLFSSL_SECQ_API int wc_SecQoriqAesGcm(int encrypt, const byte* key, word32 keySz,
    const byte* iv, word32 ivSz, const byte* aad, word32 aadSz,
    const byte* in, word32 inSz, byte* out, byte* tag, word32 tagSz);
WOLFSSL_SECQ_API int wc_SecQoriqAesGcmEncrypt(const byte* key, word32 keySz,
    const byte* iv, word32 ivSz, const byte* aad, word32 aadSz,
    const byte* in, word32 inSz, byte* out, byte* tag, word32 tagSz);
WOLFSSL_SECQ_API int wc_SecQoriqAesGcmDecrypt(const byte* key, word32 keySz,
    const byte* iv, word32 ivSz, const byte* aad, word32 aadSz,
    const byte* in, word32 inSz, byte* out, const byte* tag, word32 tagSz);
#endif

/******************************************************************************
  PKHA public key.

  The domain parameters are supplied explicitly in every descriptor. The
  engine also offers a shortcut where a small index names one of a handful of
  built in curves, but that form is refused on the parts this was written
  against; see the note above SEC_QORIQ_PKHA_PDB_L_SHIFT. Passing the
  parameters costs a few descriptor words and works for any prime curve
  wolfCrypt carries, up to the PKHA's 1023 bit ceiling.

  Every buffer below is fixed length, big endian and zero padded on the left,
  the same convention mp_to_unsigned_bin_len() produces. Public keys are the
  raw x || y pair, 2 * keySz bytes, with no leading 0x04 point format byte.
  ****************************************************************************/

/* The two PKHA users are gated independently: a build may want elliptic
 * curve work in software (to keep RFC 6979 deterministic signing, say) while
 * still offloading RSA, or the reverse. */
#if !defined(WOLFSSL_SEC_QORIQ_NO_PKHA) && defined(HAVE_ECC)
    #define WOLFSSL_SEC_QORIQ_PKHA
#endif
#if !defined(WOLFSSL_SEC_QORIQ_NO_RSA) && !defined(NO_RSA)
    #define WOLFSSL_SEC_QORIQ_RSA
#endif

#ifdef WOLFSSL_SEC_QORIQ_PKHA

/* Is this curve one the port can drive? Returns 0 if so, NOT_COMPILED_IN
 * otherwise. Any prime curve whose parameters wolfCrypt carries qualifies,
 * up to the PKHA's 1023 bit ceiling. */
WOLFSSL_SECQ_API int wc_SecQoriqEccSupported(int curveId, word32 keySz);

/* Sign a message representative. hash is the already hashed message, of any
 * length; it is reduced to the group size the way ECDSA prescribes. r and s
 * each receive keySz bytes. The engine generates the per-signature nonce
 * internally from RNG4, whose one-time bring-up happened in
 * wc_SecQoriqInit(); without a live state handle this declines with
 * NOT_COMPILED_IN so the signature falls back to software. */
WOLFSSL_SECQ_API int wc_SecQoriqEccSign(int curveId, const byte* priv,
    const byte* hash, word32 hashSz, byte* r, byte* s, word32 keySz);

/* Verify. res is set to 1 when the signature is good and 0 when it is not;
 * the return value is 0 in both of those cases and negative only when the
 * engine itself failed. */
WOLFSSL_SECQ_API int wc_SecQoriqEccVerify(int curveId, const byte* pubXY,
    const byte* hash, word32 hashSz, const byte* r, const byte* s,
    word32 keySz, int* res);

/* ECDH. out receives the x coordinate of the shared point, keySz bytes. */
WOLFSSL_SECQ_API int wc_SecQoriqEcdh(int curveId, const byte* priv,
    const byte* peerXY, byte* out, word32 keySz);

#endif /* WOLFSSL_SEC_QORIQ_PKHA */

#ifdef WOLFSSL_SEC_QORIQ_RSA

/* Largest modulus the PKHA will take, 4096 bits. */
#define SEC_QORIQ_PKHA_MAX_RSA_BYTES 512

/* First PDB word of an RSA block: the exponent length in bytes at bit 12 and
 * the modulus length in bytes at bit 0. Both fields are 12 bits. */
#define SEC_QORIQ_RSA_PDB_E_SHIFT 12
#define SEC_QORIQ_RSA_PDB_LEN_MASK 0xFFF

/* Private key form 1, the plain d and n pair. The CRT forms need the factors
 * and are not used here. */
#define SEC_QORIQ_RSA_PRIV_FRM_1 0

/* out = in^e mod n, with out and n both nSz bytes. */
WOLFSSL_SECQ_API int wc_SecQoriqRsaPublic(const byte* in, word32 inSz,
    const byte* n, word32 nSz, const byte* e, word32 eSz, byte* out);

/* out = in^d mod n, with in, out and n all nSz bytes. This is the general
 * modular exponentiation the engine offers, so it also covers finite field
 * Diffie-Hellman once wolfCrypt grows a callback hook for it. */
WOLFSSL_SECQ_API int wc_SecQoriqModExp(const byte* in, const byte* d, word32 dSz,
    const byte* n, word32 nSz, byte* out);

#endif /* WOLFSSL_SEC_QORIQ_RSA */

/******************************************************************************
  Environment seam. One backend is compiled in: sec_qoriq_baremetal.c for a
  flat physically addressed target, sec_qoriq_linux.c for user space on a
  running kernel.
  ****************************************************************************/

/* Map SEC_QORIQ_SIZE bytes of the SEC block. */
WOLFSSL_SECQ_API int   wc_SecQoriqMapRegs(byte** regsOut);
WOLFSSL_SECQ_API void  wc_SecQoriqUnmapRegs(byte* regs);

/* Allocate DMA capable memory. Must be physically contiguous, and must sit
 * below 4 GB while the driver runs in 32-bit descriptor pointer mode. */
WOLFSSL_SECQ_API void* wc_SecQoriqDmaAlloc(word32 sz, word64* physOut);
WOLFSSL_SECQ_API void  wc_SecQoriqDmaFree(void* virt, word64 phys, word32 sz);

/* Translate an address and confirm the whole length is physically
 * contiguous. The engine gets one {address, length} pair, so a buffer
 * straddling non-adjacent frames must be refused. Returns 0 if unusable.
 * Backend-internal: descriptors resolve their buffers through the per-job
 * staging hooks below, never through a bare translation. */
WOLFSSL_SECQ_API word64 wc_SecQoriqVirtToPhysLen(void* virt, word32 len);

/* Per-job DMA staging, called by wc_SecQoriqRun() with the job ring mutex
 * held, so at most one job's mappings exist at a time.
 *
 * JobBegin resets the staging state. MapBuf returns the physical address the
 * engine must use for one buffer, or 0 when it cannot be made DMA safe; the
 * mapping stays valid until JobEnd. A backend on a flat physical map returns
 * the address directly; the Linux backend copies through a pinned,
 * physically contiguous bounce arena because ordinary process pages may be
 * migrated or copied-on-write after a pagemap lookup.
 *
 * JobEnd finishes the job: with ok set, engine-written buffers are copied
 * back to their callers; staging memory is scrubbed and reclaimed either
 * way. With abandoned set the engine may still master the bus (a hung job
 * that survived every reset), so the backend must permanently retire the
 * staging memory instead of reusing it. */
WOLFSSL_SECQ_API int    wc_SecQoriqDmaJobBegin(void);
WOLFSSL_SECQ_API word64 wc_SecQoriqDmaMapBuf(void* virt, word32 sz, int dir);
WOLFSSL_SECQ_API void   wc_SecQoriqDmaJobEnd(int ok, int abandoned);

/* Cache maintenance around every descriptor and data buffer. */
WOLFSSL_SECQ_API int wc_SecQoriqCacheFlush(void* virt, word32 sz);
WOLFSSL_SECQ_API int wc_SecQoriqCacheInval(void* virt, word32 sz);

/* Zero a buffer handed to the engine and push the zeros out to memory.
 * ForceZero() alone is not enough for DMA memory: the flush that made the
 * buffer readable wrote it back and invalidated the line, so zeroing
 * afterwards only dirties cache and leaves the original bytes (a private
 * scalar, say) in DRAM. */
WOLFSSL_SECQ_API void wc_SecQoriqForceZeroDma(void* buf, word32 sz);

/* Yield briefly inside the completion poll loop. */
WOLFSSL_SECQ_API void wc_SecQoriqCpuRelax(void);

/* Read the SVR so the caller can confirm this is a security enabled part. */
WOLFSSL_SECQ_API int wc_SecQoriqGetSvr(word32* svrOut);
#define SEC_QORIQ_SVR_E_BIT 0x00080000

#ifdef WOLFSSL_SEC_QORIQ_SIM
/******************************************************************************
  Simulated backend (sec_qoriq_sim.c): a host-runnable model of the job ring
  state machine with fault injection, so the driver's submission, timeout,
  reset and status-decoding logic is exercised by make check on any machine.
  The model executes AES, GCM, hash, RNG and RSA/modexp descriptors with
  wolfCrypt's own software crypto; ECDSA/ECDH protocol jobs report a DECO
  error unless a status is injected.
  ****************************************************************************/

/* Reset the model: engine state, fault injections, RNG state handle. */
WOLFSSL_SECQ_API void wc_SecQoriqSimReset(void);
/* Force the raw status word of the next job; the job is not executed. */
WOLFSSL_SECQ_API void wc_SecQoriqSimNextStatus(word32 status);
/* The next submitted job never completes, driving the timeout path. */
WOLFSSL_SECQ_API void wc_SecQoriqSimTimeoutNext(void);
/* Make JRCR[RESET] stick (never complete) while enabled. */
WOLFSSL_SECQ_API void wc_SecQoriqSimStickJrReset(int stick);
/* Make MCFGR[DMA_RESET] stick while enabled. */
WOLFSSL_SECQ_API void wc_SecQoriqSimStickDmaReset(int stick);
/* Fail the next n RNG4 instantiation jobs, driving the entropy retry. */
WOLFSSL_SECQ_API void wc_SecQoriqSimRngFailNext(int n);
/* Entropy delay most recently programmed into RTSDCTL. */
WOLFSSL_SECQ_API word32 wc_SecQoriqSimRngEntDelay(void);
#endif /* WOLFSSL_SEC_QORIQ_SIM */

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFSSL_SEC_QORIQ */
#endif /* WOLF_CRYPT_SEC_QORIQ_H */
