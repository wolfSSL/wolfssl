/* sa2ul_driver.h
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

#ifndef SA2UL_DRIVER_H
#define SA2UL_DRIVER_H

#include <stdint.h>
#include <INTEGRITY.h>

#include <driver/soc/jacinto7/j7_dma.h>

#include <wolfssl/wolfcrypt/port/ti/integrity/sa2ul_iodevice.h>

#ifdef __cplusplus
extern "C" {
#endif

int sa2ul_driver_init(volatile void *CpAceBase, J7DmaDev *DmaDev,
        Value TxThread, Value Rx1Thread, Value Rx2Thread, Value Asel);

/* Data is the kernel mapping of the Task-shared data page. */
int sa2ul_driver_aes(struct Sa2ulCtrl *Ctrl, struct Sa2ulData *Data);

int sa2ul_driver_sha(struct Sa2ulCtrl *Ctrl, struct Sa2ulData *Data);

#ifdef __cplusplus
}
#endif

#endif /* SA2UL_DRIVER_H */
