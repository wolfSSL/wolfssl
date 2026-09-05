/* sec_qoriq_aes.c
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

/*
 * Confidentiality-only AES modes on the QorIQ SEC, driven through the AESA.
 * CBC, CTR and ECB. The authenticated modes need a different descriptor
 * shape and live elsewhere.
 *
 * Descriptor shape, following the engine's KEY -> context -> input -> output
 * ordering:
 *
 *   KEY       class 1, no write back
 *   LOAD_CTX  class 1, the IV or counter block   (CBC and CTR only)
 *   OPERATION class 1, the mode, encrypt or decrypt
 *   FIFO_LOAD class 1, the message, last
 *   FIFO_STORE            the result
 *   STORE_CTX class 1, the updated IV or counter (CBC and CTR only)
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_SEC_QORIQ) && !defined(NO_AES)

#include <wolfssl/wolfcrypt/port/nxp/sec_qoriq.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#define SEC_QORIQ_AES_BLOCK 16




static int secAesModeCtxOffset(word32 mode, word32* ofstOut, int* needsIv)
{
    switch (mode) {
        case SEC_QORIQ_AESCBC:
            *ofstOut = SEC_QORIQ_CTX_OFST_CBC;
            *needsIv = 1;
            return 0;
        case SEC_QORIQ_AESCTR:
            *ofstOut = SEC_QORIQ_CTX_OFST_CTR;
            *needsIv = 1;
            return 0;
        case SEC_QORIQ_AESECB:
            *ofstOut = 0;
            *needsIv = 0;
            return 0;
        default:
            break;
    }

    WOLFSSL_MSG("sec_qoriq: unsupported AES mode");
    return BAD_FUNC_ARG;
}

/* iv is updated in place when the mode keeps a chaining value, matching what
 * wolfCrypt expects of wc_AesCbcEncrypt and friends. */
int wc_SecQoriqAes(word32 mode, int encrypt, const byte* key, word32 keySz,
    byte* iv, const byte* in, word32 inSz, byte* out)
{
    SecQoriqDev* dev = wc_SecQoriqGetDev();
    SecQoriqDesc desc;
    word32 ofst = 0;
    int needsIv = 0;
    int ret;

    if (key == NULL || in == NULL || out == NULL) {
        return BAD_FUNC_ARG;
    }
    if (keySz != 16 && keySz != 24 && keySz != 32) {
        WOLFSSL_MSG("sec_qoriq: bad AES key size");
        return BAD_FUNC_ARG;
    }
    if (inSz == 0 || (inSz % SEC_QORIQ_AES_BLOCK) != 0) {
        /* the partial-block handling of CTR is done by the caller */
        WOLFSSL_MSG("sec_qoriq: AES input must be a whole number of blocks");
        return BAD_FUNC_ARG;
    }
    if (dev == NULL) {
        return WC_HW_E;
    }

    ret = secAesModeCtxOffset(mode, &ofst, &needsIv);
    if (ret != 0) {
        return ret;
    }
    if (needsIv && iv == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = wc_SecQoriqDescInit(&desc);
    if (ret != 0) {
        return ret;
    }

    /* NWB: the engine must not write the expanded key back to memory. */
    ret = wc_SecQoriqDescAddBuf(&desc, SEC_QORIQ_CMD_KEY | SEC_QORIQ_CLASS1 |
        SEC_QORIQ_CMD_NWB, key, keySz);
    if (ret != 0) {
        return ret;
    }

    if (needsIv) {
        ret = wc_SecQoriqDescAddBuf(&desc, SEC_QORIQ_CMD_LOAD_CTX |
            SEC_QORIQ_CLASS1 | ofst, iv, SEC_QORIQ_AES_BLOCK);
        if (ret != 0) {
            return ret;
        }
    }

    ret = wc_SecQoriqDescAddWord(&desc, SEC_QORIQ_CMD_OP | SEC_QORIQ_CLASS1 |
        mode | SEC_QORIQ_ALG_UPDATE |
        (encrypt ? SEC_QORIQ_ENC : SEC_QORIQ_DEC));
    if (ret != 0) {
        return ret;
    }

    ret = wc_SecQoriqDescAddBuf(&desc, SEC_QORIQ_CMD_FIFO_L | SEC_QORIQ_CLASS1 |
        SEC_QORIQ_FIFOL_TYPE_MSG | SEC_QORIQ_FIFOL_TYPE_LC1, in, inSz);
    if (ret != 0) {
        return ret;
    }

    ret = wc_SecQoriqDescAddBuf(&desc, SEC_QORIQ_CMD_FIFO_S |
        SEC_QORIQ_FIFOS_TYPE_MSG, out, inSz);
    if (ret != 0) {
        return ret;
    }

    if (needsIv) {
        ret = wc_SecQoriqDescAddBuf(&desc, SEC_QORIQ_CMD_STORE_CTX |
            SEC_QORIQ_CLASS1 | ofst, iv, SEC_QORIQ_AES_BLOCK);
        if (ret != 0) {
            return ret;
        }
    }

    /* Everything the engine reads has to be in memory, and anything it
     * writes must not be shadowed by a dirty line. */
    ret = wc_SecQoriqCacheFlush((void*)key, keySz);
    if (ret == 0) {
        ret = wc_SecQoriqCacheFlush((void*)in, inSz);
    }
    if (ret == 0) {
        ret = wc_SecQoriqCacheFlush(out, inSz);
    }
    if (ret == 0 && needsIv) {
        ret = wc_SecQoriqCacheFlush(iv, SEC_QORIQ_AES_BLOCK);
    }
    if (ret != 0) {
        return ret;
    }

    ret = wc_SecQoriqRun(dev, &desc);
    if (ret != 0) {
        return ret;
    }

    ret = wc_SecQoriqCacheInval(out, inSz);
    if (ret == 0 && needsIv) {
        ret = wc_SecQoriqCacheInval(iv, SEC_QORIQ_AES_BLOCK);
    }

    return ret;
}

int wc_SecQoriqAesCbcEncrypt(const byte* key, word32 keySz, byte* iv,
    const byte* in, word32 inSz, byte* out)
{
    return wc_SecQoriqAes(SEC_QORIQ_AESCBC, 1, key, keySz, iv, in, inSz, out);
}

int wc_SecQoriqAesCbcDecrypt(const byte* key, word32 keySz, byte* iv,
    const byte* in, word32 inSz, byte* out)
{
    return wc_SecQoriqAes(SEC_QORIQ_AESCBC, 0, key, keySz, iv, in, inSz, out);
}

int wc_SecQoriqAesCtrEncrypt(const byte* key, word32 keySz, byte* iv,
    const byte* in, word32 inSz, byte* out)
{
    /* CTR is its own inverse. */
    return wc_SecQoriqAes(SEC_QORIQ_AESCTR, 1, key, keySz, iv, in, inSz, out);
}

int wc_SecQoriqAesEcbEncrypt(const byte* key, word32 keySz, const byte* in,
    word32 inSz, byte* out)
{
    return wc_SecQoriqAes(SEC_QORIQ_AESECB, 1, key, keySz, NULL, in, inSz,
        out);
}

int wc_SecQoriqAesEcbDecrypt(const byte* key, word32 keySz, const byte* in,
    word32 inSz, byte* out)
{
    return wc_SecQoriqAes(SEC_QORIQ_AESECB, 0, key, keySz, NULL, in, inSz,
        out);
}

#ifdef HAVE_AESGCM

/*
 * GCM is laid out differently from the confidentiality-only modes:
 *
 *   - the OPERATION comes before the IV rather than after it, and the IV
 *     arrives as a FIFO LOAD of type IV rather than as a context load,
 *   - the output FIFO STORE is emitted before the input FIFO LOAD,
 *   - every FIFO LOAD carries FC1 (flush class 1) except the last one, which
 *     carries LC1 instead. Which load is last depends on whether there is
 *     AAD and on the direction, so the flag is patched in afterwards,
 *   - on decrypt the expected tag is loaded as type ICV and the engine does
 *     the comparison itself, reporting a mismatch as a job error.
 *
 * Unlike CBC and friends the message length is arbitrary; GCM handles a
 * partial trailing block.
 */
int wc_SecQoriqAesGcm(int encrypt, const byte* key, word32 keySz,
    const byte* iv, word32 ivSz, const byte* aad, word32 aadSz,
    const byte* in, word32 inSz, byte* out, byte* tag, word32 tagSz)
{
    SecQoriqDev* dev = wc_SecQoriqGetDev();
    SecQoriqDesc desc;
    word32 lastFifo = 0;
    int ret;

    if (key == NULL || iv == NULL || tag == NULL) {
        return BAD_FUNC_ARG;
    }
    if (in == NULL && inSz > 0) {
        return BAD_FUNC_ARG;
    }
    if (out == NULL && inSz > 0) {
        return BAD_FUNC_ARG;
    }
    if (aad == NULL && aadSz > 0) {
        return BAD_FUNC_ARG;
    }
    if (keySz != 16 && keySz != 24 && keySz != 32) {
        return BAD_FUNC_ARG;
    }
    /* Full-length tag only, enforced here at the driver boundary and not
     * just in the callback router: the engine performs the ICV comparison
     * itself and its descriptor contract does not cover truncated tags. */
    if (tagSz != SEC_QORIQ_GCM_TAG_SZ) {
        return BAD_FUNC_ARG;
    }
    /* The AESA derives J0 = IV || 0^31 || 1, which is only the SP 800-38D
     * construction for a 12 byte IV. For any other length J0 is
     * GHASH(IV || pad || len(IV)), which the engine does not do and this
     * port does not compute in software. Accepting other lengths would
     * silently produce ciphertext and tags no peer can verify. */
    if (ivSz != SEC_QORIQ_GCM_IV_SZ) {
        WOLFSSL_MSG("sec_qoriq: GCM requires a 12 byte IV");
        return BAD_FUNC_ARG;
    }
    if (dev == NULL) {
        return WC_HW_E;
    }

    ret = wc_SecQoriqDescInit(&desc);
    if (ret != 0) {
        return ret;
    }

    ret = wc_SecQoriqDescAddBuf(&desc, SEC_QORIQ_CMD_KEY | SEC_QORIQ_CLASS1 |
        SEC_QORIQ_CMD_NWB, key, keySz);
    if (ret != 0) {
        return ret;
    }

    /* INITF, not UPDATE: this is a single shot, so the engine has to both
     * initialise the GHASH state and finalise the tag. With UPDATE the
     * ciphertext still comes out correct but the stored "tag" is an
     * unfinalised intermediate. */
    ret = wc_SecQoriqDescAddWord(&desc, SEC_QORIQ_CMD_OP | SEC_QORIQ_CLASS1 |
        SEC_QORIQ_AESGCM | SEC_QORIQ_ALG_INITF |
        (encrypt ? SEC_QORIQ_ENC : (SEC_QORIQ_DEC | SEC_QORIQ_ALG_ICV)));
    if (ret != 0) {
        return ret;
    }

    lastFifo = desc.idx;
    ret = wc_SecQoriqDescAddBuf(&desc, SEC_QORIQ_CMD_FIFO_L | SEC_QORIQ_CLASS1 |
        SEC_QORIQ_FIFOL_TYPE_FC1 | SEC_QORIQ_FIFOL_TYPE_IV, iv, ivSz);
    if (ret != 0) {
        return ret;
    }

    if (aadSz > 0) {
        lastFifo = desc.idx;
        ret = wc_SecQoriqDescAddBuf(&desc, SEC_QORIQ_CMD_FIFO_L |
            SEC_QORIQ_CLASS1 | SEC_QORIQ_FIFOL_TYPE_FC1 |
            SEC_QORIQ_FIFOL_TYPE_AAD, aad, aadSz);
        if (ret != 0) {
            return ret;
        }
    }

    if (inSz > 0) {
        ret = wc_SecQoriqDescAddBuf(&desc, SEC_QORIQ_CMD_FIFO_S |
            SEC_QORIQ_FIFOS_TYPE_MSG, out, inSz);
        if (ret != 0) {
            return ret;
        }

        lastFifo = desc.idx;
        ret = wc_SecQoriqDescAddBuf(&desc, SEC_QORIQ_CMD_FIFO_L |
            SEC_QORIQ_CLASS1 | SEC_QORIQ_FIFOL_TYPE_FC1 |
            SEC_QORIQ_FIFOL_TYPE_MSG, in, inSz);
        if (ret != 0) {
            return ret;
        }
    }

    if (!encrypt) {
        /* hand the engine the tag to check against */
        lastFifo = desc.idx;
        ret = wc_SecQoriqDescAddBuf(&desc, SEC_QORIQ_CMD_FIFO_L |
            SEC_QORIQ_CLASS1 | SEC_QORIQ_FIFOL_TYPE_FC1 |
            SEC_QORIQ_FIFOL_TYPE_ICV, tag, tagSz);
        if (ret != 0) {
            return ret;
        }
    }

    /* Whichever load ended up last must terminate the class 1 stream. */
    desc.desc[lastFifo] &= ~(word32)SEC_QORIQ_FIFOL_TYPE_FC1;
    desc.desc[lastFifo] |= SEC_QORIQ_FIFOL_TYPE_LC1;

    if (encrypt) {
        ret = wc_SecQoriqDescAddBuf(&desc, SEC_QORIQ_CMD_STORE_CTX |
            SEC_QORIQ_CLASS1, tag, tagSz);
        if (ret != 0) {
            return ret;
        }
    }

    ret = wc_SecQoriqCacheFlush((void*)key, keySz);
    if (ret == 0) {
        ret = wc_SecQoriqCacheFlush((void*)iv, ivSz);
    }
    if (ret == 0 && aadSz > 0) {
        ret = wc_SecQoriqCacheFlush((void*)aad, aadSz);
    }
    if (ret == 0 && inSz > 0) {
        ret = wc_SecQoriqCacheFlush((void*)in, inSz);
    }
    if (ret == 0 && inSz > 0) {
        ret = wc_SecQoriqCacheFlush(out, inSz);
    }
    if (ret == 0) {
        ret = wc_SecQoriqCacheFlush(tag, tagSz);
    }
    if (ret != 0) {
        return ret;
    }

    ret = wc_SecQoriqRun(dev, &desc);

    /* Every failure returns here. Falling through would let the cache
     * maintenance below overwrite ret with its own success, turning a
     * hardware fault into a "decrypted" buffer the caller trusts. */
    if (ret != 0) {
        /* The engine writes the decrypted text before it checks the tag, so
         * on an authentication failure the caller's buffer already holds
         * unauthenticated plaintext. Destroy that.
         *
         * Only then, though. Any other post-submission failure propagates
         * as a hard error (see the wc_SecQoriqRun() contract), and wiping
         * the buffer would destroy the ciphertext of an in-place decrypt
         * the caller may still own. */
        if ((ret == WC_NO_ERR_TRACE(AES_GCM_AUTH_E)) && !encrypt &&
                (inSz > 0) && (out != NULL)) {
            (void)wc_SecQoriqCacheInval(out, inSz);
            ForceZero(out, inSz);
            (void)wc_SecQoriqCacheFlush(out, inSz);
        }
        return ret;
    }

    if (inSz > 0) {
        ret = wc_SecQoriqCacheInval(out, inSz);
        if (ret != 0) {
            return ret;
        }
    }
    if (encrypt) {
        ret = wc_SecQoriqCacheInval(tag, tagSz);
    }

    return ret;
}

int wc_SecQoriqAesGcmEncrypt(const byte* key, word32 keySz, const byte* iv,
    word32 ivSz, const byte* aad, word32 aadSz, const byte* in, word32 inSz,
    byte* out, byte* tag, word32 tagSz)
{
    return wc_SecQoriqAesGcm(1, key, keySz, iv, ivSz, aad, aadSz, in, inSz,
        out, tag, tagSz);
}

int wc_SecQoriqAesGcmDecrypt(const byte* key, word32 keySz, const byte* iv,
    word32 ivSz, const byte* aad, word32 aadSz, const byte* in, word32 inSz,
    byte* out, const byte* tag, word32 tagSz)
{
    /* the engine only reads the tag on decrypt, the cast keeps the public
     * shape const-correct for callers */
    return wc_SecQoriqAesGcm(0, key, keySz, iv, ivSz, aad, aadSz, in, inSz,
        out, (byte*)tag, tagSz);
}

#endif /* HAVE_AESGCM */

#endif /* WOLFSSL_SEC_QORIQ && !NO_AES */
