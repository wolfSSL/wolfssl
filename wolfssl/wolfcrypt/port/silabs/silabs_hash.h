/* silabs_hash.h
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

#ifndef _SILABS_HASH_H_
#define _SILABS_HASH_H_

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_SILABS_SE_TYPES)

#include <wolfssl/wolfcrypt/types.h>

#ifdef WOLFSSL_SILABS_HOST_TEST
    #include <wolfssl/wolfcrypt/port/silabs/silabs_shim.h>
#else
    #include <em_device.h>

    #include <sl_se_manager.h>
    #include <sl_se_manager_hash.h>
#endif

/* workaround to detect older Gecko SDK version 3 */
#if !defined(WOLFSSL_SILABS_SE_ACCEL_3) && !defined(SL_SE_PRF_HMAC_SHA1)
    /* Use streaming instead of new multipart */
    #define WOLFSSL_SILABS_SE_ACCEL_3
#endif

/* SHA-384 and SHA-512 need Secure Vault High. WOLFSSL_SILABS_SE_SHA384/512
 * mean "the SE can do it" and gate the SE context and the callback port. */
#if (_SILICON_LABS_SECURITY_FEATURE == _SILICON_LABS_SECURITY_FEATURE_VAULT)
    #ifdef WOLFSSL_SHA384
        #define WOLFSSL_SILABS_SE_SHA384
    #endif
    #ifdef WOLFSSL_SHA512
        #define WOLFSSL_SILABS_SE_SHA512
    #endif
#endif

/* WOLFSSL_SILABS_SHA384/512 additionally mean "replace the software
 * implementation", which is only true for the direct port. The callback port
 * keeps software compiled in so an unsupported request can fall back. */
#ifdef WOLFSSL_SILABS_SE_ACCEL
    #ifdef WOLFSSL_SILABS_SE_SHA384
        #define WOLFSSL_SILABS_SHA384
    #endif
    #ifdef WOLFSSL_SILABS_SE_SHA512
        #define WOLFSSL_SILABS_SHA512
    #endif
#endif

#ifdef WOLFSSL_SILABS_SE_ACCEL_3
/* Gecko SDK v3 uses "streaming" interface */
typedef struct {
    sl_se_hash_streaming_context_t hash_ctx;
    sl_se_command_context_t cmd_ctx;
    union hash_type_ctx_u {
        sl_se_sha1_streaming_context_t   sha1_ctx;
        sl_se_sha224_streaming_context_t sha224_ctx;
        sl_se_sha256_streaming_context_t sha256_ctx;
    #ifdef WOLFSSL_SILABS_SE_SHA384
        sl_se_sha384_streaming_context_t sha384_ctx;
    #endif
    #ifdef WOLFSSL_SILABS_SE_SHA512
        sl_se_sha512_streaming_context_t sha512_ctx;
    #endif
    } hash_type_ctx;
    /* Set once the SE context has been started. The crypto callback port has
     * no hook on wc_InitShaXXX, so it starts the SE lazily on the first
     * update or final; wc_InitShaXXX zeroes the struct, clearing this. */
    byte started;
} wc_silabs_sha_t;
#else
/* Gecko SDK v4 or later uses "multipart" interface */
typedef struct {
    sl_se_command_context_t cmd_ctx;
    union hash_type_ctx_u {
        sl_se_sha1_multipart_context_t   sha1_ctx;
        sl_se_sha224_multipart_context_t sha224_ctx;
        sl_se_sha256_multipart_context_t sha256_ctx;
    #ifdef WOLFSSL_SILABS_SE_SHA384
        sl_se_sha384_multipart_context_t sha384_ctx;
    #endif
    #ifdef WOLFSSL_SILABS_SE_SHA512
        sl_se_sha512_multipart_context_t sha512_ctx;
    #endif
    } hash_type_ctx;
    /* See the note on the streaming variant above. */
    byte started;
} wc_silabs_sha_t;
#endif

/* Return the raw SE Manager status so callers can separate an unsupported
 * command from a hardware failure. */
int wc_silabs_se_hash_init_status(wc_silabs_sha_t* sha, enum wc_HashType type);
int wc_silabs_se_hash_update_status(wc_silabs_sha_t* sha, const byte* data,
    word32 len);
int wc_silabs_se_hash_final_status(wc_silabs_sha_t* sha, byte* hash,
    word32 len);

int wc_silabs_se_hash_init(wc_silabs_sha_t* sha, enum wc_HashType type);
int wc_silabs_se_hash_update(wc_silabs_sha_t* sha, const byte* data,
    word32 len);
int wc_silabs_se_hash_final(wc_silabs_sha_t* sha, byte* hash, word32 len);



#endif /* WOLFSSL_SILABS_SE_TYPES */

#endif /* _SILABS_HASH_H_ */
