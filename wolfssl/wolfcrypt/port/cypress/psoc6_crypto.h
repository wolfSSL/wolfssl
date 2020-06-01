/* psoc6_crypto.h
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
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

#ifndef _PSOC6_CRYPTO_PORT_H_
#define _PSOC6_CRYPTO_PORT_H_

#include <wolfssl/wolfcrypt/settings.h>
#ifdef USE_FAST_MATH
    #include <wolfssl/wolfcrypt/tfm.h>
#elif defined WOLFSSL_SP_MATH
    #include <wolfssl/wolfcrypt/sp_int.h>
#else
    #include <wolfssl/wolfcrypt/integer.h>
#endif
#include "cy_crypto_core_sha.h"
#include "cy_device_headers.h"
#include "psoc6_02_config.h"
#include "cy_crypto_common.h"
#include "cy_crypto_core.h"

#ifndef NO_SHA256

#include "cy_crypto_core_sha.h"
typedef struct wc_Sha256 {
    cy_stc_crypto_sha_state_t hash_state;
    cy_en_crypto_sha_mode_t sha_mode;
    cy_stc_crypto_v2_sha256_buffers_t sha_buffers;
} wc_Sha256;


#endif /* !def NO_SHA256 */

#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>

#define PSOC6_CRYPTO_BASE ((CRYPTO_Type*) CRYPTO_BASE)

/* Crypto HW engine initialization */
int psoc6_crypto_port_init(void);

#endif /* _PSOC6_CRYPTO_PORT_H_ */
