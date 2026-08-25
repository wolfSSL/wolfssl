/* silabs_aes.h
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

#ifndef _SILABS_AES_H_
#define _SILABS_AES_H_

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_SILABS_SE_TYPES)

#include <wolfssl/wolfcrypt/types.h>

#ifdef WOLFSSL_SILABS_HOST_TEST
    #include <wolfssl/wolfcrypt/port/silabs/silabs_shim.h>
#else
    #include <em_device.h>

    #include <sl_se_manager.h>
    #include <sl_se_manager_cipher.h>
#endif

typedef struct {
  sl_se_command_context_t cmd_ctx;
  sl_se_key_descriptor_t  key;
  /* Non-zero once wc_SilabsSe_AesUseWrappedKey() or
   * wc_SilabsSe_AesUseBuiltInKey() has bound a device-resident key. The crypto
   * callback port then leaves the descriptor alone instead of rebuilding it
   * from the plaintext key each operation. */
  byte keySet;
} silabs_aes_t;

typedef struct Aes Aes;

/* Shared SE helpers, used by both the direct port (WOLFSSL_SILABS_SE_ACCEL)
 * and the crypto callback port. */
int silabs_aes_init_key_desc(silabs_aes_t* ctx, const byte* key, word32 keylen);
int silabs_aes_ecb(Aes* aes, byte* out, const byte* in, word32 sz,
    sl_se_cipher_operation_t dir);
int silabs_aes_cbc(Aes* aes, byte* out, const byte* in, word32 sz,
    sl_se_cipher_operation_t dir);

/* Raw-status forms of the above. A negative return is a wolfCrypt argument
 * error; anything else is the SE status unchanged, so a caller can separate an
 * unsupported command from a hardware failure and decline rather than fail.
 * The crypto callback port uses these; the direct port uses the wrappers. */
int silabs_aes_ecb_status(Aes* aes, byte* out, const byte* in, word32 sz,
    sl_se_cipher_operation_t dir);
int silabs_aes_cbc_status(Aes* aes, byte* out, const byte* in, word32 sz,
    sl_se_cipher_operation_t dir);

#if defined(WOLFSSL_SILABS_SE_ACCEL) && defined(WOLFSSL_AES_DIRECT)
int wc_AesEncrypt(Aes* aes, const byte* inBlock, byte* outBlock);
int wc_AesDecrypt(Aes* aes, const byte* inBlock, byte* outBlock);
#endif

#ifdef HAVE_AESGCM
int wc_AesGcmEncrypt_silabs (Aes* aes, byte* out, const byte* in, word32 sz,
                             const byte* iv, word32 ivSz,
                             byte* authTag, word32 authTagSz,
                             const byte* authIn, word32 authInSz);
int wc_AesGcmDecrypt_silabs (Aes* aes, byte* out, const byte* in, word32 sz,
                             const byte* iv, word32 ivSz,
                             const byte* authTag, word32 authTagSz,
                             const byte* authIn, word32 authInSz);

int wc_AesGcmEncrypt_silabs_status (Aes* aes, byte* out, const byte* in,
                             word32 sz, const byte* iv, word32 ivSz,
                             byte* authTag, word32 authTagSz,
                             const byte* authIn, word32 authInSz);
int wc_AesGcmDecrypt_silabs_status (Aes* aes, byte* out, const byte* in,
                             word32 sz, const byte* iv, word32 ivSz,
                             const byte* authTag, word32 authTagSz,
                             const byte* authIn, word32 authInSz);

#endif /* HAVE_AESGCM */

#ifdef HAVE_AESCCM
int wc_AesCcmEncrypt_silabs (Aes* aes, byte* out, const byte* in, word32 sz,
                             const byte* iv, word32 ivSz,
                             byte* authTag, word32 authTagSz,
                             const byte* authIn, word32 authInSz);
int wc_AesCcmDecrypt_silabs (Aes* aes, byte* out, const byte* in, word32 sz,
                             const byte* iv, word32 ivSz,
                             const byte* authTag, word32 authTagSz,
                             const byte* authIn, word32 authInSz);

int wc_AesCcmEncrypt_silabs_status (Aes* aes, byte* out, const byte* in,
                             word32 sz, const byte* iv, word32 ivSz,
                             byte* authTag, word32 authTagSz,
                             const byte* authIn, word32 authInSz);
int wc_AesCcmDecrypt_silabs_status (Aes* aes, byte* out, const byte* in,
                             word32 sz, const byte* iv, word32 ivSz,
                             const byte* authTag, word32 authTagSz,
                             const byte* authIn, word32 authInSz);

#endif /* HAVE_AESCCM */

#endif /* defined(WOLFSSL_SILABS_SE_TYPES) */

#endif /* _SILABS_AES_H_ */
