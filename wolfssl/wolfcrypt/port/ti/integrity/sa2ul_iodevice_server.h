/* sa2ul_iodevice_server.h
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

#ifndef SA2UL_IODEVICE_SERVER_H
#define SA2UL_IODEVICE_SERVER_H

#ifdef INTEGRITY

#include <INTEGRITY.h>

#ifdef __cplusplus
extern "C" {
#endif

void sa2ul_iodevice_attach_shared_pages(void *Ctrl, Address CtrlLen,
                                        void *Data, Address DataLen);

#ifdef __cplusplus
}
#endif

#endif /* INTEGRITY */
#endif /* SA2UL_IODEVICE_SERVER_H */
