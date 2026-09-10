/* silabs_ecc.h
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


#ifndef _SILABS_ECC_H_
#define _SILABS_ECC_H_

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_SILABS_SE_TYPES)

#include <wolfssl/wolfcrypt/types.h>

#ifdef WOLFSSL_SILABS_HOST_TEST
    #include <wolfssl/wolfcrypt/port/silabs/silabs_shim.h>
#else
    #include <sl_se_manager.h>
    #include <sl_se_manager_defines.h>
    #include <sl_se_manager_key_derivation.h>
    #include <sl_se_manager_signature.h>
#endif

typedef struct ecc_key ecc_key;

int silabs_ecc_sign_hash (const byte* in, word32 inlen,
                          byte* out, word32 *outlen,
                          ecc_key* key);
/* Raw-status form: negative is a wolfCrypt error, otherwise the SE status
 * unchanged, so the crypto callback port can map an unsupported command to
 * CRYPTOCB_UNAVAILABLE and fall back instead of hard-failing. */
int silabs_ecc_sign_hash_status (const byte* in, word32 inlen,
                          byte* out, word32 *outlen,
                          ecc_key* key);
int silabs_ecc_verify_hash (const byte* sig, word32 siglen,
                            const byte* hash, word32 hashlen,
                            int* stat, ecc_key* key);
int silabs_ecc_verify_hash_status (const byte* sig, word32 siglen,
                            const byte* hash, word32 hashlen,
                            int* stat, ecc_key* key);


int silabs_ecc_make_key(ecc_key* key, int keysize);
int silabs_ecc_make_key_status(ecc_key* key, int keysize);

int silabs_ecc_import(ecc_key* key, word32 keysize, int pub, int priv);
int silabs_ecc_export_public(ecc_key* key, sl_se_key_descriptor_t* seKey);

int silabs_ecc_shared_secret(ecc_key* private_key, ecc_key* public_key,
                             byte* out, word32* outlen);
int silabs_ecc_shared_secret_status(ecc_key* private_key, ecc_key* public_key,
                             byte* out, word32* outlen);

#if (_SILICON_LABS_SECURITY_FEATURE == _SILICON_LABS_SECURITY_FEATURE_VAULT)
int silabs_ecc_load_vault(ecc_key* key);
#endif


#endif /* WOLFSSL_SILABS_SE_TYPES */

#endif /* _SILABS_ECC_H_ */
