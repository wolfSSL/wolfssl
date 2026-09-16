/* sa2ul_iodevice.h
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

#ifndef SA2UL_IODEVICE_H
#define SA2UL_IODEVICE_H

#include <stdint.h>

#define SA2UL_IODEVICE_NAME "Sa2ulDev"

/* non-zero status number (arbitrary) */
#define SA2UL_IODEVICE_STATUS_NUMBER 1

/* Largest single buffer this driver moves through SA2UL per call */
#define SA2UL_MAX_BUF 4096u

#define SA2UL_MAX_KEY_BYTES 32u
#define SA2UL_MAX_IV_BYTES  16u
#define SA2UL_MAX_AAD_BYTES 16u
#define SA2UL_MAX_TAG_BYTES 16u
#define SA2UL_MAX_HASH_BYTES 64u

enum Sa2ulOp {
    SA2UL_OP_AES_ECB_ENCRYPT = 0,
    SA2UL_OP_AES_ECB_DECRYPT,
    SA2UL_OP_AES_CBC_ENCRYPT,
    SA2UL_OP_AES_CBC_DECRYPT,
    SA2UL_OP_AES_GCM_ENCRYPT,
    SA2UL_OP_AES_GCM_DECRYPT,
    SA2UL_OP_SHA1,
    SA2UL_OP_SHA256,
    SA2UL_OP_SHA512,
    SA2UL_OP_SHA224,
    SA2UL_OP_SHA384
};

/* struct Sa2ulCtrl.ret's values -- set by sa2ul_driver_aes()/
 * sa2ul_driver_sha() (sa2ul_driver.c, Kernel-linked) and read back by
 * ti_sa2ul_IodeviceCall() (sa2ul_port.c, Task-linked). */
#define SA2UL_DRIVER_OK             0
#define SA2UL_DRIVER_BAD_ARG        1  /* bad size/key length/etc. */
#define SA2UL_DRIVER_NOT_READY      2  /* sa2ul_driver_set_dma() never called
                                        * / hardware bring-up failed */
#define SA2UL_DRIVER_HW_ERROR       3  /* channel/ring/context alloc or
                                        * process failure */
#define SA2UL_DRIVER_AUTH_FAILED    4  /* GCM decrypt: computed tag didn't
                                        * match the caller-supplied one */

struct Sa2ulCtrl {
    /* --- filled in by the Task before triggering the op --- */
    uint32_t op;          /* enum Sa2ulOp */
    uint32_t sz;          /* input/output length in bytes, <= SA2UL_MAX_BUF;
                           * for GCM, the ciphertext/plaintext length
                           * (not counting the tag); for SHA*, the
                           * message length to hash */
    uint32_t keyBytes;    /* 16, 24 or 32 -- AES ops only */
    uint32_t ivSz;        /* CBC/ECB: 16 (ECB ignores this); GCM: 12 --
                           * AES ops only */
    uint32_t aadSz;       /* GCM only, <= SA2UL_MAX_AAD_BYTES; 0 for ECB/CBC */
    uint32_t tagSz;       /* GCM only, 1..SA2UL_MAX_TAG_BYTES: bytes of
                           * tagOut produced / tagIn compared */
    uint8_t  key[SA2UL_MAX_KEY_BYTES];
    uint8_t  iv[SA2UL_MAX_IV_BYTES];
    uint8_t  aad[SA2UL_MAX_AAD_BYTES];
    uint8_t  tagIn[SA2UL_MAX_TAG_BYTES];  /* GCM decrypt: tag to verify */

    /* in:  ghashValid=1 -> ghash holds H for this key; driver skips the
     *      extra ECB pass that derives it
     * out: driver sets ghashValid=1 and fills ghash whenever it derived H
     *      itself, so the Task can cache it with the key */
    uint32_t ghashValid;
    uint8_t  ghash[16];

    /* --- filled in by the Kernel-side driver before returning --- */
    uint32_t ret;              /* 0 on success, nonzero on failure (see
                                * sa2ul_driver.h's SA2UL_DRIVER_* codes) */
    uint8_t  tagOut[SA2UL_MAX_TAG_BYTES]; /* GCM encrypt: computed tag */
    uint8_t  digestOut[SA2UL_MAX_HASH_BYTES]; /* SHA*: computed digest --
                                * 20/32/64 valid bytes for SHA1/256/512
                                * respectively, rest unwritten */
};

/* The buffer itself lives in a separate 1-page shared Object
 * ("sa2ul_data_phys"/"sa2ul_data_local" in myproject.int). It is only
 * touched by the CPU; the kernel driver copies it to/from its own DMA
 * bounce buffer. */
struct Sa2ulData {
    uint8_t buf[SA2UL_MAX_BUF];
};

#endif /* SA2UL_IODEVICE_H */
