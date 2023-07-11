/* ext_lms.c
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>

#ifdef WOLFSSL_HAVE_LMS
#include <wolfssl/wolfcrypt/ext_lms.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/* The hash-sigs hss_generate_private_key API requires a generate_random
 * callback that only has output and length args. The RNG struct must be global
 * to the function. Maybe there should be a wc_LmsKey_SetRngCb. */
static THREAD_LS_T WC_RNG * LmsRng = NULL;

static bool LmsGenerateRand(void * output, size_t length)
{
    int ret = 0;

    if (output == NULL || LmsRng == NULL) {
        return false;
    }

    if (length == 0) {
        return true;
    }

    ret = wc_RNG_GenerateBlock(LmsRng, output, (word32) length);

    if (ret) {
        WOLFSSL_MSG("error: LmsGenerateRand failed");
        return false;
    }

    return true;
}

/* Write callback passed into hash-sigs hss lib. */
static bool LmsWritePrivKey(unsigned char *private_key,
                            size_t len_private_key, void *lmsKey)
{
    LmsKey *      key = (LmsKey *) lmsKey;
    enum wc_LmsRc ret = WC_LMS_RC_NONE;

    if (private_key == NULL || key == NULL || len_private_key <= 0) {
        WOLFSSL_MSG("error: LmsWritePrivKey: invalid args");
        return false;
    }

    if (key->state != WC_LMS_STATE_INITED && key->state != WC_LMS_STATE_OK) {
       /* The key had an error the last time it was used, and we
        * can't guarantee its state. */
        WOLFSSL_MSG("error: LmsWritePrivKey: LMS key not in good state");
        return false;
    }

    if (key->write_private_key == NULL) {
        WOLFSSL_MSG("error: LmsWritePrivKey: LMS key write callback not set");
        key->state = WC_LMS_STATE_NOT_INITED;
        return false;
    }

    /* Use write callback. */
    ret = key->write_private_key(private_key, len_private_key, key->context);

    if (ret != WC_LMS_RC_SAVED_TO_NV_MEMORY) {
        WOLFSSL_MSG("error: LmsKey write_private_key failed");
        WOLFSSL_MSG(wc_LmsKey_RcToStr(ret));
        key->state = WC_LMS_STATE_BAD;
        return false;
    }

    return true;
}

/* Read callback passed into hash-sigs hss lib. */
static bool LmsReadPrivKey(unsigned char *private_key,
                           size_t len_private_key, void *lmsKey)
{
    LmsKey *      key = (LmsKey *) lmsKey;
    enum wc_LmsRc ret = WC_LMS_RC_NONE;

    if (private_key == NULL || key == NULL || len_private_key <= 0) {
        WOLFSSL_MSG("error: LmsReadPrivKey: invalid args");
        return false;
    }

    if (key->state != WC_LMS_STATE_INITED && key->state != WC_LMS_STATE_OK) {
       /* The key had an error the last time it was used, and we
        * can't guarantee its state. */
        WOLFSSL_MSG("error: LmsReadPrivKey: LMS key not in good state");
        return false;
    }

    if (key->read_private_key == NULL) {
        WOLFSSL_MSG("error: LmsReadPrivKey: LMS key read callback not set");
        key->state = WC_LMS_STATE_NOT_INITED;
        return false;
    }

    /* Use read callback. */
    ret = key->read_private_key(private_key, len_private_key, key->context);

    if (ret != WC_LMS_RC_READ_TO_MEMORY) {
        WOLFSSL_MSG("error: LmsKey read_private_key failed");
        WOLFSSL_MSG(wc_LmsKey_RcToStr(ret));
        key->state = WC_LMS_STATE_BAD;
        return false;
    }

    return true;
}

const char * wc_LmsKey_ParmToStr(enum wc_LmsParm lmsParm)
{
    switch (lmsParm) {
    case WC_LMS_PARM_NONE:
        return "LMS_NONE";

    case WC_LMS_PARM_L1_H15_W2:
        return "LMS/HSS L1_H15_W2";

    case WC_LMS_PARM_L1_H15_W4:
        return "LMS/HSS L1_H15_W4";

    case WC_LMS_PARM_L2_H10_W2:
        return "LMS/HSS L2_H10_W2";

    case WC_LMS_PARM_L2_H10_W4:
        return "LMS/HSS L2_H10_W4";

    case WC_LMS_PARM_L2_H10_W8:
        return "LMS/HSS L2_H10_W8";

    case WC_LMS_PARM_L3_H5_W2:
        return "LMS/HSS L3_H5_W2";

    case WC_LMS_PARM_L3_H5_W4:
        return "LMS/HSS L3_H5_W4";

    case WC_LMS_PARM_L3_H5_W8:
        return "LMS/HSS L3_H5_W8";

    case WC_LMS_PARM_L3_H10_W4:
        return "LMS/HSS L3_H10_W4";

    case WC_LMS_PARM_L4_H5_W8:
        return "LMS/HSS L4_H5_W8";

    default:
        WOLFSSL_MSG("error: invalid LMS parameter");
        break;
    }

    return "LMS_INVALID";
}

const char * wc_LmsKey_RcToStr(enum wc_LmsRc lmsEc)
{
    switch (lmsEc) {
    case WC_LMS_RC_NONE:
        return "LMS_RC_NONE";

    case WC_LMS_RC_BAD_ARG:
        return "LMS_RC_BAD_ARG";

    case WC_LMS_RC_WRITE_FAIL:
        return "LMS_RC_WRITE_FAIL";

    case WC_LMS_RC_READ_FAIL:
        return "LMS_RC_READ_FAIL";

    case WC_LMS_RC_SAVED_TO_NV_MEMORY:
        return "LMS_RC_SAVED_TO_NV_MEMORY";

    case WC_LMS_RC_READ_TO_MEMORY:
        return "LMS_RC_READ_TO_MEMORY";

    default:
        WOLFSSL_MSG("error: invalid LMS error code");
        break;
    }

    return "LMS_RC_INVALID";
}

int wc_LmsKey_Init(LmsKey * key, enum wc_LmsParm lmsParm)
{
    if (key == NULL) {
        return BAD_FUNC_ARG;
    }

    switch (lmsParm) {
    case WC_LMS_PARM_NONE:
        return wc_LmsKey_Init_ex(key, 1, 15, 2, NULL, INVALID_DEVID);

    case WC_LMS_PARM_L1_H15_W2:
        return wc_LmsKey_Init_ex(key, 1, 15, 2, NULL, INVALID_DEVID);

    case WC_LMS_PARM_L1_H15_W4:
        return wc_LmsKey_Init_ex(key, 1, 15, 4, NULL, INVALID_DEVID);

    case WC_LMS_PARM_L2_H10_W2:
        return wc_LmsKey_Init_ex(key, 2, 10, 2, NULL, INVALID_DEVID);

    case WC_LMS_PARM_L2_H10_W4:
        return wc_LmsKey_Init_ex(key, 2, 10, 4, NULL, INVALID_DEVID);

    case WC_LMS_PARM_L2_H10_W8:
        return wc_LmsKey_Init_ex(key, 2, 10, 8, NULL, INVALID_DEVID);

    case WC_LMS_PARM_L3_H5_W2:
        return wc_LmsKey_Init_ex(key, 3, 5, 2, NULL, INVALID_DEVID);

    case WC_LMS_PARM_L3_H5_W4:
        return wc_LmsKey_Init_ex(key, 3, 5, 4, NULL, INVALID_DEVID);

    case WC_LMS_PARM_L3_H5_W8:
        return wc_LmsKey_Init_ex(key, 3, 5, 8, NULL, INVALID_DEVID);

    case WC_LMS_PARM_L3_H10_W4:
        return wc_LmsKey_Init_ex(key, 3, 10, 4, NULL, INVALID_DEVID);

    case WC_LMS_PARM_L4_H5_W8:
        return wc_LmsKey_Init_ex(key, 4, 5, 8, NULL, INVALID_DEVID);

    default:
        WOLFSSL_MSG("error: invalid LMS parameter set");
        break;
    }

    return BAD_FUNC_ARG;
}

int wc_LmsKey_Init_ex(LmsKey * key, int levels, int height,
    int winternitz, void* heap, int devId)
{
    int         ret = 0;
    int         i = 0;
    param_set_t lm = LMS_SHA256_N32_H5;
    param_set_t ots = LMOTS_SHA256_N32_W8;
    (void)      heap;
    (void)      devId;

    key->state = WC_LMS_STATE_NOT_INITED;

    if (key == NULL) {
        return BAD_FUNC_ARG;
    }

    ForceZero(key, sizeof(LmsKey));

    /* Verify inputs make sense. Values of 0 may be passed to signify
     * using minimum defaults. */
    if (levels == 0) {
        levels = MIN_HSS_LEVELS;
    }
    else if (levels < MIN_HSS_LEVELS || levels > MAX_HSS_LEVELS) {
        WOLFSSL_MSG("error: invalid level parameter");
        return BAD_FUNC_ARG;
    }

    if (height == 0) {
        height = MIN_MERKLE_HEIGHT;
    }
    else if (height < MIN_MERKLE_HEIGHT || height > MAX_MERKLE_HEIGHT) {
        WOLFSSL_MSG("error: invalid height parameter");
        return BAD_FUNC_ARG;
    }

    if (winternitz == 0) {
        winternitz = 2;
    }

    switch (height) {
    case 5:
        lm = LMS_SHA256_N32_H5;
        break;
    case 10:
        lm = LMS_SHA256_N32_H10;
        break;
    case 15:
        lm = LMS_SHA256_N32_H15;
        break;
    case 20:
        lm = LMS_SHA256_N32_H20;
        break;
    case 25:
        lm = LMS_SHA256_N32_H25;
        break;
    default:
        WOLFSSL_MSG("error: invalid height parameter");
        return BAD_FUNC_ARG;
    }

    switch (winternitz) {
    case 1:
        ots = LMOTS_SHA256_N32_W1;
        break;
    case 2:
        ots = LMOTS_SHA256_N32_W2;
        break;
    case 4:
        ots = LMOTS_SHA256_N32_W4;
        break;
    case 8:
        ots = LMOTS_SHA256_N32_W8;
        break;
    default:
        WOLFSSL_MSG("error: invalid winternitz parameter");
        return BAD_FUNC_ARG;
    }

    key->levels = levels;

    for (i = 0; i < levels; ++i) {
        key->lm_type[i] = lm;
        key->lm_ots_type[i] = ots;
    }

    hss_init_extra_info(&key->info);

    key->working_key = NULL;
    key->write_private_key = NULL;
    key->read_private_key = NULL;
    key->context = NULL;
    key->state = WC_LMS_STATE_INITED;

    return ret;
}

void wc_LmsKey_Free(LmsKey* key)
{
    if (key == NULL) {
        return;
    }

    if (key->working_key != NULL) {
        hss_free_working_key(key->working_key);
        key->working_key = NULL;
    }

    ForceZero(key, sizeof(LmsKey));

    key->state = WC_LMS_STATE_NOT_INITED;

    return;
}

int  wc_LmsKey_MakeKey(LmsKey* key, WC_RNG * rng)
{
    bool result = true;

    if (key == NULL || rng == NULL) {
        return BAD_FUNC_ARG;
    }

    if (key->state != WC_LMS_STATE_INITED) {
        WOLFSSL_MSG("error: LmsKey not ready for generation");
        return -1;
    }

    if (key->write_private_key == NULL || key->read_private_key == NULL) {
        WOLFSSL_MSG("error: LmsKey write/read callbacks are not set");
        return -1;
    }

    if (key->context == NULL) {
        WOLFSSL_MSG("error: LmsKey context is not set");
        return -1;
    }

    LmsRng = rng;

   /* TODO: The hash-sigs lib allows you to save variable length auxiliary
    * data, which can be used to speed up key reloading when signing. The
    * aux data can be 300B - 1KB in size.
    *
    * Not implemented at the moment.
    *
    * key->aux_data_len = hss_get_aux_data_len(AUX_DATA_MAX_LEN, key->levels,
    *                                          key->lm_type,
    *                                          key->lm_ots_type);
    *
    * key->aux_data = XMALLOC(key->aux_data_len, NULL,
    *                         DYNAMIC_TYPE_TMP_BUFFER);
    */

    result = hss_generate_private_key(LmsGenerateRand, key->levels,
                                      key->lm_type, key->lm_ots_type,
                                      LmsWritePrivKey, key,
                                      key->pub, sizeof(key->pub),
                                      NULL, 0, &key->info);

    if (!result) {
        WOLFSSL_MSG("error: hss_generate_private_key failed");
        key->state = WC_LMS_STATE_BAD;
        return -1;
    }

    key->working_key = hss_load_private_key(LmsReadPrivKey, key,
                                            0, NULL, 0, &key->info);

    if (key->working_key == NULL) {
        WOLFSSL_MSG("error: hss_load_private_key failed");
        key->state = WC_LMS_STATE_BAD;
        return -1;
    }

    key->state = WC_LMS_STATE_OK;

    return 0;
}

int wc_LmsKey_SetWriteCb(LmsKey * key, write_private_key_cb write_cb)
{
    if (key == NULL || write_cb == NULL) {
        return BAD_FUNC_ARG;
    }

    key->write_private_key = write_cb;

    return 0;
}

int wc_LmsKey_SetReadCb(LmsKey * key, read_private_key_cb read_cb)
{
    if (key == NULL || read_cb == NULL) {
        return BAD_FUNC_ARG;
    }

    key->read_private_key = read_cb;

    return 0;
}

/* Sets the context to be used by write and read callbacks.
 * E.g. this could be a filename if the callbacks write/read to file. */
int wc_LmsKey_SetContext(LmsKey * key, void * context)
{
    if (key == NULL || context == NULL) {
        return BAD_FUNC_ARG;
    }

    key->context = context;

    return 0;
}

/* Reload a key that has been prepared with the appropriate read callbacks
 * or data. */
int wc_LmsKey_Reload(LmsKey * key)
{
    bool result = true;

    if (key == NULL) {
        return BAD_FUNC_ARG;
    }

    if (key->state != WC_LMS_STATE_INITED) {
        WOLFSSL_MSG("error: LmsKey not ready for reload");
        return -1;
    }

    if (key->write_private_key == NULL || key->read_private_key == NULL) {
        WOLFSSL_MSG("error: LmsKey write/read callbacks are not set");
        return -1;
    }

    if (key->context == NULL) {
        WOLFSSL_MSG("error: LmsKey context is not set");
        return -1;
    }

    key->working_key = hss_load_private_key(LmsReadPrivKey, key,
                                            0, NULL, 0, &key->info);

    if (key->working_key == NULL) {
        WOLFSSL_MSG("error: hss_load_private_key failed");
        key->state = WC_LMS_STATE_BAD;
        return -1;
    }

    result = hss_get_parameter_set(&key->levels, key->lm_type,
                                   key->lm_ots_type, LmsReadPrivKey, key);

    if (!result) {
        WOLFSSL_MSG("error: hss_get_parameter_set failed");
        key->state = WC_LMS_STATE_BAD;
        hss_free_working_key(key->working_key);
        key->working_key = NULL;
        return -1;
    }

    key->state = WC_LMS_STATE_OK;

    return 0;
}

/* Given a levels, height, winternitz parameter set, determine
 * the private key length */
int  wc_LmsKey_GetPrivLen(LmsKey * key, word32 * len)
{
    if (key == NULL || len == NULL) {
        return BAD_FUNC_ARG;
    }

    *len = (word32) hss_get_private_key_len(key->levels, key->lm_type,
                                            key->lm_ots_type);

    return 0;
}

/* Given a levels, height, winternitz parameter set, determine
 * the public key length */
int  wc_LmsKey_GetPubLen(LmsKey * key, word32 * len)
{
    if (key == NULL || len == NULL) {
        return BAD_FUNC_ARG;
    }

    *len = (word32) hss_get_public_key_len(key->levels, key->lm_type,
                                           key->lm_ots_type);

    return 0;
}

/* Export a generated public key. Use this to prepare a signature verification
 * key that is pub only. */
int  wc_LmsKey_ExportPub(LmsKey * keyDst, const LmsKey * keySrc)
{
    if (keyDst == NULL || keySrc == NULL) {
        return BAD_FUNC_ARG;
    }

    ForceZero(keyDst, sizeof(LmsKey));

    XMEMCPY(keyDst->pub, keySrc->pub, sizeof(keySrc->pub));
    XMEMCPY(keyDst->lm_type, keySrc->lm_type, sizeof(keySrc->lm_type));
    XMEMCPY(keyDst->lm_ots_type, keySrc->lm_ots_type,
            sizeof(keySrc->lm_ots_type));

    keyDst->levels = keySrc->levels;
    keyDst->state = keySrc->state;

    return 0;
}

/* Given a levels, height, winternitz parameter set, determine
 * the signature length.
 *
 * Call this before wc_LmsKey_Sign so you know the length of
 * the required sig buffer. */
int  wc_LmsKey_GetSigLen(LmsKey * key, word32 * len)
{
    if (key == NULL || len == NULL) {
        return BAD_FUNC_ARG;
    }

    *len = (word32) hss_get_signature_len(key->levels, key->lm_type,
                                          key->lm_ots_type);

    return 0;
}

int wc_LmsKey_Sign(LmsKey* key, byte * sig, word32 * sigSz, const byte * msg,
    int msgSz)
{
    bool   result = true;
    size_t len = 0;

    if (key == NULL || sig == NULL || sigSz == NULL || msg == NULL) {
        return BAD_FUNC_ARG;
    }

    if (msgSz <= 0) {
        return BAD_FUNC_ARG;
    }

    if (key->state == WC_LMS_STATE_NOSIGS) {
        WOLFSSL_MSG("error: LMS signatures exhausted");
        return -1;
    }
    else if (key->state != WC_LMS_STATE_OK) {
       /* The key had an error the last time it was used, and we
        * can't guarantee its state. */
        WOLFSSL_MSG("error: can't sign, LMS key not in good state");
        return -1;
    }

    len = hss_get_signature_len(key->levels, key->lm_type, key->lm_ots_type);

    if (len == 0) {
        /* Key parameters are invalid. */
        WOLFSSL_MSG("error: hss_get_signature_len failed");
        key->state = WC_LMS_STATE_BAD;
        return -1;
    }

    result = hss_generate_signature(key->working_key, LmsWritePrivKey,
                                    key, (const void *) msg, msgSz,
                                    sig, len, &key->info);

    if (!result) {
        if (wc_LmsKey_SigsLeft(key) == 0) {
            WOLFSSL_MSG("error: LMS signatures exhausted");
            key->state = WC_LMS_STATE_NOSIGS;
            return -1;
        }

        WOLFSSL_MSG("error: hss_generate_signature failed");
        key->state = WC_LMS_STATE_BAD;
        return -1;
    }

    *sigSz = (word32) len;

    return 0;
}

int wc_LmsKey_Verify(LmsKey * key, const byte * sig, word32 sigSz,
    const byte * msg, int msgSz)
{
    bool result = true;

    if (key == NULL || sig == NULL || msg == NULL) {
        return BAD_FUNC_ARG;
    }

    result = hss_validate_signature(key->pub, (const void *) msg, msgSz, sig,
                                    sigSz, &key->info);

    if (!result) {
        WOLFSSL_MSG("error: hss_validate_signature failed");
        return -1;
    }

    return 0;
}

int  wc_LmsKey_SigsLeft(LmsKey * key)
{
    /* Returns 1 if there are signatures remaining.
     * Returns 0 if available signatures are exhausted.
     *
     * Note: the number of remaining signatures is hidden behind an opaque
     * pointer in the hash-sigs lib. We could add a counter here that is
     * decremented on every signature. The number of available signatures
     * grows as
     *   N = 2 ** (levels * height)
     * so it would need to be a big integer. */

    if (key == NULL) {
        return BAD_FUNC_ARG;
    }

    if (hss_extra_info_test_last_signature(&key->info)) {
        return 0;
    }

    return 1;
}
#endif /* WOLFSSL_HAVE_LMS */
