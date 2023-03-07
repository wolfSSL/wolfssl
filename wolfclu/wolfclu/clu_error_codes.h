/* clu_error_codes.h
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
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

#ifndef _WOLFSSL_CLU_ERROR_H_
#define _WOLFSSL_CLU_ERROR_H_

#define WOLFCLU_FATAL_ERROR -1
#define WOLFCLU_FAILURE 0
#define WOLFCLU_SUCCESS 1

enum {

    USER_INPUT_ERROR = -1001,
    INPUT_FILE_ERROR = -1002,
    PEM_TO_DER_ERROR = -1003, /* converting pem to der failed */
    DER_TO_PEM_ERROR = -1004, /* converting der to pem failed */
    OUTPUT_FILE_ERROR = -1005,
    FEATURE_COMING_SOON = -1006, /* Feature not yet implemented */
};

#endif /* _WOLFSSL_CLU_ERROR_H_ */
