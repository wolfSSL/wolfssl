/* silabs_aes.c
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

/* Generic SILABS Series2 AES support Function */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif


#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_SILABS_SE_TYPES)


#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/port/silabs/silabs_aes.h>


/* Build a plaintext-key SE key descriptor for keylen bytes held at key. The
 * descriptor points at the caller's buffer, so that buffer must outlive it.
 * Shared by the direct port below and by the crypto callback port. */
int silabs_aes_init_key_desc(silabs_aes_t* ctx, const byte* key, word32 keylen)
{
    sl_se_command_context_t cc = SL_SE_COMMAND_CONTEXT_INIT;
    int ret = 0;

    if (ctx == NULL || key == NULL) {
        return BAD_FUNC_ARG;
    }

    ctx->cmd_ctx = cc;
    XMEMSET(&(ctx->key), 0, sizeof(sl_se_key_descriptor_t));
    ctx->key.storage.method = SL_SE_KEY_STORAGE_EXTERNAL_PLAINTEXT;

    switch (keylen) {
    case 128/8:
        ctx->key.type = SL_SE_KEY_TYPE_AES_128;
        break;
#ifdef WOLFSSL_AES_192
    case 192/8:
        ctx->key.type = SL_SE_KEY_TYPE_AES_192;
        break;
#endif
#ifdef WOLFSSL_AES_256
    case 256/8:
        ctx->key.type = SL_SE_KEY_TYPE_AES_256;
        break;
#endif
    default:
        ret = BAD_FUNC_ARG;
        break;
    }

    if (ret == 0) {
        ctx->key.storage.location.buffer.pointer = (void*)key;
        ctx->key.storage.location.buffer.size = keylen;
        ctx->key.size = keylen;
    }

    return ret;
}

/* Raw ECB. sz must already be a multiple of the block size; callers check. */
/* Raw-status ECB. Returns a negative wolfCrypt error for an argument problem,
 * otherwise the SE status unchanged so the caller can tell an unsupported
 * command from a hardware failure. The crypto callback port needs that
 * distinction to fall back to software; the direct port does not, and its
 * wrapper below keeps the original contract. */
int silabs_aes_ecb_status(Aes* aes, byte* out, const byte* in, word32 sz,
    sl_se_cipher_operation_t dir)
{
    if ((in == NULL) || (out == NULL) || (aes == NULL)) {
        return BAD_FUNC_ARG;
    }

    return (int)sl_se_aes_crypt_ecb(
        &(aes->ctx.cmd_ctx),
        &(aes->ctx.key),
        dir,
        sz,
        in,
        out);
}

int silabs_aes_ecb(Aes* aes, byte* out, const byte* in, word32 sz,
    sl_se_cipher_operation_t dir)
{
    int status = silabs_aes_ecb_status(aes, out, in, sz, dir);

    if (status < 0) {
        return status;
    }
    return (status != SL_STATUS_OK) ? WC_HW_E : 0;
}

/* Raw CBC. The working IV is aes->reg, updated in place by the SE. */
/* Raw-status CBC; see silabs_aes_ecb_status() for the return convention. */
int silabs_aes_cbc_status(Aes* aes, byte* out, const byte* in, word32 sz,
    sl_se_cipher_operation_t dir)
{
    if ((in == NULL) || (out == NULL) || (aes == NULL)) {
        return BAD_FUNC_ARG;
    }

    return (int)sl_se_aes_crypt_cbc(
        &(aes->ctx.cmd_ctx),
        &(aes->ctx.key),
        dir,
        sz,
        (uint8_t*)aes->reg,
        in,
        out);
}

int silabs_aes_cbc(Aes* aes, byte* out, const byte* in, word32 sz,
    sl_se_cipher_operation_t dir)
{
    int status = silabs_aes_cbc_status(aes, out, in, sz, dir);

    if (status < 0) {
        return status;
    }
    return (status != SL_STATUS_OK) ? WC_HW_E : 0;
}


#if defined(WOLFSSL_SILABS_SE_ACCEL)
/* Below this point the SE replaces the software implementation outright. The
 * crypto callback port leaves the software versions in place and reaches the
 * SE through the helpers above instead. */

int wc_AesSetKey(Aes* aes, const byte* userKey, word32 keylen,
                 const byte* iv, int dir)
{
    int ret = 0;
    (void)dir;

    if (aes == NULL || userKey == NULL || keylen > sizeof(aes->key)) {
        return BAD_FUNC_ARG;
    }

    ret = sl_se_init();
    if (ret != SL_STATUS_OK) {
        return WC_HW_E;
    }

    XMEMSET(aes, 0, sizeof(*aes));

    ret = wc_AesSetIV(aes, iv);
    if (ret != 0)
        return ret;
    aes->rounds = keylen/4 + 6;

    XMEMCPY(aes->key, userKey, keylen);
    ret = silabs_aes_init_key_desc(&(aes->ctx), (const byte*)aes->key, keylen);
    if (ret == 0) {
        /* Mark key installed so the shared aes.c mode guards accept this
         * context. */
        aes->keyInstalled = 1;
    }

    return ret;
}

#ifdef HAVE_AES_ECB
int wc_AesEcbEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    if ((sz % WC_AES_BLOCK_SIZE) != 0) {
        return BAD_LENGTH_E;
    }
    return silabs_aes_ecb(aes, out, in, sz, SL_SE_ENCRYPT);
}

int wc_AesEcbDecrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    if ((sz % WC_AES_BLOCK_SIZE) != 0) {
        return BAD_LENGTH_E;
    }
    return silabs_aes_ecb(aes, out, in, sz, SL_SE_DECRYPT);
}
#endif /* HAVE_AES_ECB */

#ifdef WOLFSSL_AES_DIRECT
int wc_AesEncrypt(Aes* aes, const byte* inBlock, byte* outBlock)
{
    return silabs_aes_ecb(aes, outBlock, inBlock, WC_AES_BLOCK_SIZE,
        SL_SE_ENCRYPT);
}

int wc_AesDecrypt(Aes* aes, const byte* inBlock, byte* outBlock)
{
    return silabs_aes_ecb(aes, outBlock, inBlock, WC_AES_BLOCK_SIZE,
        SL_SE_DECRYPT);
}
#endif /* WOLFSSL_AES_DIRECT */

int wc_AesCbcEncrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    return silabs_aes_cbc(aes, out, in, sz, SL_SE_ENCRYPT);
}

int wc_AesCbcDecrypt(Aes* aes, byte* out, const byte* in, word32 sz)
{
    return silabs_aes_cbc(aes, out, in, sz, SL_SE_DECRYPT);
}

#endif /* WOLFSSL_SILABS_SE_ACCEL */

#ifdef HAVE_AESGCM
int wc_AesGcmEncrypt_silabs_status (Aes* aes, byte* out, const byte* in, word32 sz,
                            const byte* iv, word32 ivSz,
                            byte* authTag, word32 authTagSz,
                            const byte* authIn, word32 authInSz)
{
    sl_status_t status;
    if ((in == NULL) || (out == NULL) || (iv == NULL) || (authTag == NULL) ||
            (authIn == NULL && authInSz != 0) || (aes == NULL)) {
        return BAD_FUNC_ARG;
    }

    status = sl_se_gcm_crypt_and_tag(
        &(aes->ctx.cmd_ctx),
        &(aes->ctx.key),
        SL_SE_ENCRYPT,
        sz,
        iv,
        ivSz,
        authIn,
        authInSz,
        in,
        out,
        authTagSz,
        authTag);

    return (int)status;
}

int wc_AesGcmEncrypt_silabs (Aes* aes, byte* out, const byte* in, word32 sz,
                             const byte* iv, word32 ivSz,
                             byte* authTag, word32 authTagSz,
                             const byte* authIn, word32 authInSz)
{
    int status = wc_AesGcmEncrypt_silabs_status(aes, out, in, sz, iv, ivSz, authTag, authTagSz, authIn, authInSz);

    if (status < 0) {
        return status;
    }
    return (status != SL_STATUS_OK) ? AES_GCM_AUTH_E : 0;
}

int wc_AesGcmDecrypt_silabs_status (Aes* aes, byte* out, const byte* in, word32 sz,
                            const byte* iv, word32 ivSz,
                            const byte* authTag, word32 authTagSz,
                            const byte* authIn, word32 authInSz)
{
    sl_status_t status;
    if ((in == NULL) || (out == NULL) || (iv == NULL) || (authTag == NULL) ||
            (authIn == NULL && authInSz != 0) || (aes == NULL)) {
        return BAD_FUNC_ARG;
    }

    status = sl_se_gcm_auth_decrypt(
        &(aes->ctx.cmd_ctx),
        &(aes->ctx.key),
        sz,
        iv,
        ivSz,
        authIn,
        authInSz,
        in,
        out,
        authTagSz,
        (byte*)authTag);

    return (int)status;
}

int wc_AesGcmDecrypt_silabs (Aes* aes, byte* out, const byte* in, word32 sz,
                             const byte* iv, word32 ivSz,
                             const byte* authTag, word32 authTagSz,
                             const byte* authIn, word32 authInSz)
{
    int status = wc_AesGcmDecrypt_silabs_status(aes, out, in, sz, iv, ivSz, authTag, authTagSz, authIn, authInSz);

    if (status < 0) {
        return status;
    }
    return (status != SL_STATUS_OK) ? AES_GCM_AUTH_E : 0;
}

#endif /* HAVE_AESGCM */


#ifdef HAVE_AESCCM
int wc_AesCcmEncrypt_silabs_status (Aes* aes, byte* out, const byte* in, word32 sz,
                             const byte* iv, word32 ivSz,
                             byte* authTag, word32 authTagSz,
                             const byte* authIn, word32 authInSz)
{
    sl_status_t status;
    if ((in == NULL) || (out == NULL) || (iv == NULL) || (authTag == NULL) ||
            (ivSz < CCM_NONCE_MIN_SZ) || (ivSz > CCM_NONCE_MAX_SZ) ||
            (authIn == NULL && authInSz != 0) || (aes == NULL)) {
        return BAD_FUNC_ARG;
    }

    {
        word32 lenSz = (word32)WC_AES_BLOCK_SIZE - 1U - ivSz;
        /* With a large nonce, B[] runs out of room to represent inSz, and beyond
         * that, the counter itself can wrap.
         */
        if ((lenSz < sizeof(sz)) &&
            (sz >= ((word32)1 << (lenSz * 8))))
        {
            return AES_CCM_OVERFLOW_E;
        }
    }

    status = sl_se_ccm_encrypt_and_tag(
        &(aes->ctx.cmd_ctx),
        &(aes->ctx.key),
        sz,
        iv,
        ivSz,
        authIn,
        authInSz,
        in,
        out,
        authTag,
        authTagSz
        );

    return (int)status;
}

int wc_AesCcmEncrypt_silabs (Aes* aes, byte* out, const byte* in, word32 sz,
                             const byte* iv, word32 ivSz,
                             byte* authTag, word32 authTagSz,
                             const byte* authIn, word32 authInSz)
{
    int status = wc_AesCcmEncrypt_silabs_status(aes, out, in, sz, iv, ivSz, authTag, authTagSz, authIn, authInSz);

    if (status < 0) {
        return status;
    }
    return (status != SL_STATUS_OK) ? AES_CCM_AUTH_E : 0;
}

int wc_AesCcmDecrypt_silabs_status (Aes* aes, byte* out, const byte* in, word32 sz,
                            const byte* iv, word32 ivSz,
                            const byte* authTag, word32 authTagSz,
                            const byte* authIn, word32 authInSz)
{
    sl_status_t status;
    if ((in == NULL) || (out == NULL) || (iv == NULL) || (authTag == NULL) ||
            (ivSz < CCM_NONCE_MIN_SZ) || (ivSz > CCM_NONCE_MAX_SZ) ||
            (authIn == NULL && authInSz != 0) || (aes == NULL)) {
        return BAD_FUNC_ARG;
    }

    {
        word32 lenSz = (word32)WC_AES_BLOCK_SIZE - 1U - ivSz;
        /* With a large nonce, B[] runs out of room to represent inSz, and beyond
         * that, the counter itself can wrap.
         */
        if ((lenSz < sizeof(sz)) &&
            (sz >= ((word32)1 << (lenSz * 8))))
        {
            return AES_CCM_OVERFLOW_E;
        }
    }

    status = sl_se_ccm_auth_decrypt(
        &(aes->ctx.cmd_ctx),
        &(aes->ctx.key),
        sz,
        iv,
        ivSz,
        authIn,
        authInSz,
        in,
        out,
        (byte*)authTag,
        authTagSz);

    return (int)status;
}

int wc_AesCcmDecrypt_silabs (Aes* aes, byte* out, const byte* in, word32 sz,
                             const byte* iv, word32 ivSz,
                             const byte* authTag, word32 authTagSz,
                             const byte* authIn, word32 authInSz)
{
    int status = wc_AesCcmDecrypt_silabs_status(aes, out, in, sz, iv, ivSz, authTag, authTagSz, authIn, authInSz);

    if (status < 0) {
        return status;
    }
    return (status != SL_STATUS_OK) ? AES_CCM_AUTH_E : 0;
}

#endif /* HAVE_AESCCM */

#endif /* WOLFSSL_SILABS_SE_TYPES */
