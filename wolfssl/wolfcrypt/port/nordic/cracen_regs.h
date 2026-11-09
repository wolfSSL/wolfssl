/* cracen_regs.h
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

/* nRF54L CRACEN register map and Cryptomaster encodings.
 *
 * Sources:
 * - Register offsets, bit positions and reset values: nRF54L15/L10/L05
 *   Datasheet v1.0 section 7.8.1 and the Nordic MDK device header
 *   (nrf54l15_application.h, BSD-3-Clause).
 * - DMA descriptor layout, tag bit fields, AES register offsets and AES
 *   configuration word: nrfx helpers/nrf_cracen_cm_dma.h (BSD-3-Clause).
 * - Hash configuration word (algorithm select, hardware padding, final),
 *   the invalid-byte count carried in the tag of a data block, the AES
 *   context load/save bits for CMAC/GCM and the exported state sizes: hardware
 *   behaviour of the BA411E/BA413 engines as programmed by Nordic's nRF
 *   Connect SDK CRACEN driver, recorded here as register facts.
 */

#ifndef WOLFSSL_CRACEN_REGS_H
#define WOLFSSL_CRACEN_REGS_H

/* Peripheral bases (secure mapping; CRACEN is a secure-only peripheral) */
#define WC_CRACEN_BASE                  0x50048000UL
#define WC_CRACENCORE_BASE              0x51800000UL

/* CRACEN wrapper */
#define WC_CRACEN_EVENTS_CRYPTOMASTER   0x100UL
#define WC_CRACEN_EVENTS_RNG            0x104UL
#define WC_CRACEN_EVENTS_PKEIKG         0x108UL
#define WC_CRACEN_ENABLE                0x400UL
#define WC_CRACEN_ENABLE_CRYPTOMASTER   (1UL << 0)
#define WC_CRACEN_ENABLE_RNG            (1UL << 1)
#define WC_CRACEN_ENABLE_PKEIKG         (1UL << 2)

/* CRACENCORE: Cryptomaster DMA */
#define WC_CM_FETCHADDR                 0x000UL
#define WC_CM_FETCHLEN                  0x008UL
#define WC_CM_FETCHTAG                  0x00CUL
#define WC_CM_PUSHADDR                  0x010UL
#define WC_CM_PUSHLEN                   0x018UL
#define WC_CM_INTEN                     0x01CUL
#define WC_CM_INTSTATRAW                0x028UL
#define WC_CM_INTSTAT                   0x02CUL
#define WC_CM_INTSTATCLR                0x030UL
#define WC_CM_CONFIG                    0x034UL
#define WC_CM_START                     0x038UL
#define WC_CM_STATUS                    0x03CUL

#define WC_CM_CONFIG_FETCH_INDIRECT     (1UL << 0)
#define WC_CM_CONFIG_PUSH_INDIRECT      (1UL << 1)
#define WC_CM_CONFIG_FETCH_STOP         (1UL << 2)
#define WC_CM_CONFIG_PUSH_STOP          (1UL << 3)
#define WC_CM_CONFIG_SOFTRST            (1UL << 4)

#define WC_CM_START_FETCH               (1UL << 0)
#define WC_CM_START_PUSH                (1UL << 1)

#define WC_CM_STATUS_FETCH_BUSY         (1UL << 0)
#define WC_CM_STATUS_PUSH_BUSY          (1UL << 1)
#define WC_CM_STATUS_FETCH_NOT_EMPTY    (1UL << 4)
#define WC_CM_STATUS_PUSH_WAITING       (1UL << 5)
#define WC_CM_STATUS_SOFTRST_BUSY       (1UL << 6)
#define WC_CM_STATUS_BUSY_MASK \
    (WC_CM_STATUS_FETCH_BUSY | WC_CM_STATUS_PUSH_BUSY | WC_CM_STATUS_PUSH_WAITING)

#define WC_CM_INT_FETCH_BLOCK_END       (1UL << 0)
#define WC_CM_INT_FETCH_STOPPED         (1UL << 1)
#define WC_CM_INT_FETCH_ERROR           (1UL << 2)
#define WC_CM_INT_PUSH_BLOCK_END        (1UL << 3)
#define WC_CM_INT_PUSH_STOPPED          (1UL << 4)
#define WC_CM_INT_PUSH_ERROR            (1UL << 5)

/* CRACENCORE: Cryptomaster hardware configuration (read only) */
#define WC_CM_HW_INCLIPS                0x400UL
#define WC_CM_HW_BA411_CFG1             0x404UL  /* AES: supported modes      */
#define WC_CM_HW_BA411_CFG2             0x408UL  /* AES: CTR counter size     */
#define WC_CM_HW_BA413_CFG              0x40CUL  /* Hash: algorithms, padding */
#define WC_CM_HW_BA418_CFG              0x410UL
#define WC_CM_HW_BA419_CFG              0x414UL

#define WC_CM_HW_BA411_AES              (1UL << 0)
#define WC_CM_HW_BA415_AESGCM           (1UL << 1)
#define WC_CM_HW_BA416_AESXTS           (1UL << 2)
#define WC_CM_HW_BA412_DES              (1UL << 3)
#define WC_CM_HW_BA413_HASH             (1UL << 4)
#define WC_CM_HW_BA417_CHACHAPOLY       (1UL << 5)
#define WC_CM_HW_BA418_SHA3             (1UL << 6)
#define WC_CM_HW_BA419_SM4              (1UL << 8)
#define WC_CM_HW_BA414EP_PKE            (1UL << 9)
#define WC_CM_HW_BA431_NDRNG            (1UL << 10)

#define WC_CM_HW_BA411_MODES_MASK       0x1FFUL  /* one bit per mode id       */
#define WC_CM_HW_BA413_ALGO_MASK        0x7FUL   /* one bit per algorithm     */
#define WC_CM_HW_BA413_HW_PADDING       (1UL << 16)
#define WC_CM_HW_BA413_HMAC             (1UL << 17)

/* DMA descriptor (16 bytes, 4-byte aligned, in RAM) */
#define WC_CM_DESC_STOP                 1UL          /* next: end of chain   */
#define WC_CM_LEN_MASK                  0x0FFFFFFFUL
#define WC_CM_LEN_CONST_ADDR            (1UL << 28)
#define WC_CM_LEN_REALIGN               (1UL << 29)  /* pad to 32-bit bus    */
#define WC_CM_LEN_DISCARD               (1UL << 30)  /* pusher only          */
#define WC_CM_LEN_INT_EN                (1UL << 31)
#define WC_CM_MAX_LEN                   (1UL << 24)

/* Fetch tag */
#define WC_CM_TAG_ENGINE_AES            0x1UL
#define WC_CM_TAG_ENGINE_HASH           0x3UL
#define WC_CM_TAG_CONFIG                (1UL << 4)   /* engine register write */
#define WC_CM_TAG_LAST                  (1UL << 5)
#define WC_CM_TAG_DATATYPE(x)           ((word32)(x) << 6)
#define WC_CM_TAG_REGOFF(o)             ((word32)(o) << 8)
#define WC_CM_TAG_IGN(n)                ((word32)(n) << 8) /* invalid tail bytes, 0..31 */

/* AES engine (BA411E) */
#define WC_CM_AES_REG_CONFIG            0x00UL
#define WC_CM_AES_REG_KEY               0x08UL  /* up to 32 bytes        */
#define WC_CM_AES_REG_IV                0x28UL  /* 16 bytes, also state  */
#define WC_CM_AES_REG_IV2               0x38UL  /* 16 bytes              */
#define WC_CM_AES_REG_KEY2              0x48UL  /* XTS tweak key         */
#define WC_CM_AES_REG_MASK              0x68UL  /* countermeasure LFSR   */

#define WC_CM_AES_TAG_CFG(reg) \
    (WC_CM_TAG_ENGINE_AES | WC_CM_TAG_CONFIG | WC_CM_TAG_REGOFF(reg))
#define WC_CM_AES_TAG_PAYLOAD           (WC_CM_TAG_ENGINE_AES | WC_CM_TAG_DATATYPE(0))
#define WC_CM_AES_TAG_HEADER            (WC_CM_TAG_ENGINE_AES | WC_CM_TAG_DATATYPE(1))

#define WC_CM_AES_CFG_DECRYPT           (1UL << 0)
#define WC_CM_AES_CFG_CTX_LOAD          (1UL << 4)
#define WC_CM_AES_CFG_CTX_SAVE          (1UL << 5)
#define WC_CM_AES_CFG_KEYSEL_LO(k)      (((word32)(k) & 0x3UL) << 6)
#define WC_CM_AES_CFG_KEYSEL_HI(k)      ((((word32)(k) >> 2) & 0x7UL) << 28)
#define WC_CM_AES_CFG_MODE_SHIFT        8
#define WC_CM_AES_MODE_ECB              (1UL << 8)
#define WC_CM_AES_MODE_CBC              (1UL << 9)
#define WC_CM_AES_MODE_CTR              (1UL << 10)
#define WC_CM_AES_MODE_CFB              (1UL << 11)
#define WC_CM_AES_MODE_OFB              (1UL << 12)
#define WC_CM_AES_MODE_CCM              (1UL << 13)
#define WC_CM_AES_MODE_GCM              (1UL << 14)
#define WC_CM_AES_MODE_XTS              (1UL << 15)
#define WC_CM_AES_MODE_CMAC             (1UL << 16)

/* Hash engine (BA413) */
#define WC_CM_HASH_TAG_CFG              (WC_CM_TAG_ENGINE_HASH | WC_CM_TAG_CONFIG)
#define WC_CM_HASH_TAG_MESSAGE          (WC_CM_TAG_ENGINE_HASH | WC_CM_TAG_DATATYPE(0))
#define WC_CM_HASH_TAG_INIT_STATE       (WC_CM_TAG_ENGINE_HASH | WC_CM_TAG_DATATYPE(1))
#define WC_CM_HASH_TAG_HMAC_KEY         (WC_CM_TAG_ENGINE_HASH | WC_CM_TAG_DATATYPE(2))

#define WC_CM_HASH_ALGO_MD5             0x01UL
#define WC_CM_HASH_ALGO_SHA1            0x02UL
#define WC_CM_HASH_ALGO_SHA224          0x04UL
#define WC_CM_HASH_ALGO_SHA256          0x08UL
#define WC_CM_HASH_ALGO_SHA384          0x10UL
#define WC_CM_HASH_ALGO_SHA512          0x20UL
#define WC_CM_HASH_ALGO_SM3             0x40UL
#define WC_CM_HASH_CFG_HW_PAD           (1UL << 9)
#define WC_CM_HASH_CFG_FINAL            (1UL << 10) /* clear: export state  */

/* CRACENCORE: RNG (BA431) */
#define WC_RNG_CONTROL                  0x1000UL
#define WC_RNG_FIFOLEVEL                0x1004UL
#define WC_RNG_FIFOTHRESHOLD            0x1008UL
#define WC_RNG_FIFODEPTH                0x100CUL
#define WC_RNG_KEY0                     0x1010UL /* KEY[0..3]            */
#define WC_RNG_REPEATTHRESHOLD          0x1024UL
#define WC_RNG_PROPTHRESHOLD            0x1028UL
#define WC_RNG_STATUS                   0x1030UL
#define WC_RNG_INITWAITVAL              0x1034UL
#define WC_RNG_DISABLEOSC0              0x1038UL
#define WC_RNG_SWOFFTMRVAL              0x1040UL
#define WC_RNG_CLKDIV                   0x1044UL
#define WC_RNG_HWCONFIG                 0x1058UL
#define WC_RNG_FIFO                     0x1080UL /* FIFO[0..15]          */

#define WC_RNG_CONTROL_ENABLE           (1UL << 0)
#define WC_RNG_CONTROL_LFSREN           (1UL << 1)
#define WC_RNG_CONTROL_TESTEN           (1UL << 2)
#define WC_RNG_CONTROL_CONDBYPASS       (1UL << 3)
#define WC_RNG_CONTROL_INTENREP         (1UL << 4)
#define WC_RNG_CONTROL_INTENPROP        (1UL << 5)
#define WC_RNG_CONTROL_INTENFULL        (1UL << 7)
#define WC_RNG_CONTROL_SOFTRST          (1UL << 8)
#define WC_RNG_CONTROL_INTENPRE         (1UL << 9)
#define WC_RNG_CONTROL_INTENALM         (1UL << 10)
#define WC_RNG_CONTROL_FORCEACTIVEROS   (1UL << 11)
#define WC_RNG_CONTROL_HEALTHTESTBYPASS (1UL << 12)
#define WC_RNG_CONTROL_AIS31BYPASS      (1UL << 13)
#define WC_RNG_CONTROL_HEALTHTESTSEL    (1UL << 14)
#define WC_RNG_CONTROL_AIS31TESTSEL     (1UL << 15)
#define WC_RNG_CONTROL_NB128_SHIFT      16
#define WC_RNG_CONTROL_NB128(n)         ((word32)(n) << WC_RNG_CONTROL_NB128_SHIFT)
#define WC_RNG_CONTROL_FIFOWRITESTARTUP (1UL << 20)

#define WC_RNG_STATUS_TESTDATABUSY      (1UL << 0)
#define WC_RNG_STATUS_STATE_SHIFT       1
#define WC_RNG_STATUS_STATE_MASK        0x7UL
#define WC_RNG_STATUS_REPFAIL           (1UL << 4)
#define WC_RNG_STATUS_PROPFAIL          (1UL << 5)
#define WC_RNG_STATUS_FULLINT           (1UL << 7)
#define WC_RNG_STATUS_PREINT            (1UL << 8)
#define WC_RNG_STATUS_ALMINT            (1UL << 9)
#define WC_RNG_STATUS_STARTUPFAIL       (1UL << 10)
#define WC_RNG_STATUS_FIFOACCFAIL       (1UL << 11)

#define WC_RNG_STATE_RESET              0
#define WC_RNG_STATE_STARTUP            1
#define WC_RNG_STATE_IDLE_RINGS_ON      2
#define WC_RNG_STATE_IDLE_RINGS_OFF     3
#define WC_RNG_STATE_FILL_FIFO          4
#define WC_RNG_STATE_ERROR              5

#endif /* WOLFSSL_CRACEN_REGS_H */
