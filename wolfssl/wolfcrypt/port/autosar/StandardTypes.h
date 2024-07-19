/* StandardTypes.h
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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

#ifdef WOLFSSL_AUTOSAR

#ifndef WOLFSSL_STANDARDTYPES_H
#define WOLFSSL_STANDARDTYPES_H
#include <wolfssl/wolfcrypt/types.h>

/* remap primitives */
typedef byte   uint8;
typedef byte   boolean;
typedef word16 uint16;
typedef word32 uint32;
typedef word64 uint64;

#ifndef TRUE
    #define TRUE 1
#endif
#ifndef FALSE
    #define FALSE 0
#endif

/* return types */
typedef enum Std_ReturnType {
    E_OK = 0x00,
    E_NOT_OK = 0x01,
    E_SMALL_BUFFER = 0x02,
    E_ENTROPY_EXHAUSTION = 0x03,
    E_KEY_READ_FAIL = 0x04,
    E_KEY_NOT_AVAILABLE = 0x05,
    E_KEY_NOT_VALID = 0x06,
    E_JOB_CANCELED = 0x07,
    E_KEY_EMPTY = 0x08
} Std_ReturnType;


typedef struct Std_VersionInfoType {
    uint16 vendorID;
    uint16 moduleID;
    uint8 sw_major_version;
    uint8 sw_minor_version;
    uint8 sw_patch_version;
} Std_VersionInfoType;
#endif /* WOLFSSL_AUTOSAR */

#endif /* WOLFSSL_STANDARDTYPES_H */

