/* wc_lms.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>

#if defined(WOLFSSL_HAVE_LMS) && defined(WOLFSSL_WC_LMS)
#include <wolfssl/wolfcrypt/wc_lms.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif


/* Calculate u. Appendix B. Works for w of 1, 2, 4, or 8.
 *
 * @param [in] w  Winternitz width.
 */
#define LMS_U(w)                    \
    (8 * WC_SHA256_DIGEST_SIZE / (w))
/* Calculate u. Appendix B. Works for w of 1, 2, 4, or 8.
 *
 * @param [in] w   Winternitz width.
 * @param [in] wb  Winternitz width length in bits.
 */
#define LMS_V(w, wb)                \
    (2 + (8 - (wb)) / (w))
/* Calculate ls. Appendix B. Works for w of 1, 2, 4, or 8.
 *
 * @param [in] w   Winternitz width.
 * @param [in] wb  Winternitz width length in bits.
 */
#define LMS_LS(w, wb)               \
    (16 - LMS_V(w, wb) * (w))
/* Calculate p. Appendix B. Works for w of 1, 2, 4, or 8.
 *
 * @param [in] w   Winternitz width.
 * @param [in] wb  Winternitz width length in bits.
 */
#define LMS_P(w, wb)                \
    (LMS_U(w) + LMS_V(w, wb))
/* Calculate signature length.
 *
 * @param [in] l  Number of levels.
 * @param [in] h  Height of the trees.
 * @param [in] p  Number of n-byte string elements in signature for a tree.
 */
#define LMS_PARAMS_SIG_LEN(l, h, p)                                     \
    (4 + (l) * (4 + 4 + 4 + WC_SHA256_DIGEST_SIZE * (1 + (p) + (h))) +  \
     ((l) - 1) * LMS_PUBKEY_LEN)

#ifndef WOLFSSL_WC_LMS_SMALL
    /* Root levels and leaf cache bits. */
    #define LMS_PARAMS_CACHE(h)                             \
        (((h) < LMS_ROOT_LEVELS) ? (h) : LMS_ROOT_LEVELS),  \
        (((h) < LMS_CACHE_BITS ) ? (h) : LMS_CACHE_BITS )
#else
    /* Root levels and leaf cache bits aren't in structure. */
    #define LMS_PARAMS_CACHE(h) /* null expansion */
#endif

/* Define parameters entry for LMS.
 *
 * @param [in] l   Number of levels.
 * @param [in] h   Height of the trees.
 * @param [in] w   Winternitz width.
 * @param [in] wb  Winternitz width length in bits.
 * @param [in] t   LMS type.
 * @param [in] t2  LM-OTS type.
 */
#define LMS_PARAMS(l, h, w, wb, t, t2)                              \
    { l, h, w, LMS_LS(w, wb), LMS_P(w, wb), t, t2,                  \
      LMS_PARAMS_SIG_LEN(l, h, LMS_P(w, wb)), LMS_PARAMS_CACHE(h) }


/* Initialize the working state for LMS operations.
 *
 * @param [in, out] state   LMS state.
 * @param [in]      params  LMS parameters.
 */
static int wc_lmskey_state_init(LmsState* state, const LmsParams* params)
{
    int ret;

    /* Zero out every field. */
    XMEMSET(state, 0, sizeof(LmsState));

    /* Keep a reference to the parameters for use in operations. */
    state->params = params;

    /* Initialize the two hash algorithms. */
    ret = wc_InitSha256(&state->hash);
    if (ret == 0) {
        ret = wc_InitSha256(&state->hash_k);
        if (ret != 0) {
            wc_Sha256Free(&state->hash);
        }
    }

    return ret;
}

/* Free the working state for LMS operations.
 *
 * @param [in] state  LMS state.
 */
static void wc_lmskey_state_free(LmsState* state)
{
    wc_Sha256Free(&state->hash_k);
    wc_Sha256Free(&state->hash);
}

/* Supported LMS parameters. */
static const wc_LmsParamsMap wc_lms_map[] = {
#if LMS_MAX_HEIGHT >= 15
    { WC_LMS_PARM_NONE     , "LMS_NONE"         ,
      LMS_PARAMS(1, 15, 2, 1, LMS_SHA256_M32_H15, LMOTS_SHA256_N32_W2) },
    { WC_LMS_PARM_L1_H15_W2, "LMS/HSS L1_H15_W2",
      LMS_PARAMS(1, 15, 2, 1, LMS_SHA256_M32_H15, LMOTS_SHA256_N32_W2) },
    { WC_LMS_PARM_L1_H15_W4, "LMS/HSS L1_H15_W4",
      LMS_PARAMS(1, 15, 4, 2, LMS_SHA256_M32_H15, LMOTS_SHA256_N32_W4) },
#endif
#if LMS_MAX_LEVELS >= 2
#if LMS_MAX_HEIGHT >= 10
    { WC_LMS_PARM_L2_H10_W2, "LMS/HSS L2_H10_W2",
      LMS_PARAMS(2, 10, 2, 1, LMS_SHA256_M32_H10, LMOTS_SHA256_N32_W2) },
    { WC_LMS_PARM_L2_H10_W4, "LMS/HSS L2_H10_W4",
      LMS_PARAMS(2, 10, 4, 2, LMS_SHA256_M32_H10, LMOTS_SHA256_N32_W4) },
    { WC_LMS_PARM_L2_H10_W8, "LMS/HSS L2_H10_W8",
      LMS_PARAMS(2, 10, 8, 3, LMS_SHA256_M32_H10, LMOTS_SHA256_N32_W8) },
#endif
#endif
#if LMS_MAX_LEVELS >= 3
    { WC_LMS_PARM_L3_H5_W2 , "LMS/HSS L3_H5_W2" ,
      LMS_PARAMS(3,  5, 2, 1, LMS_SHA256_M32_H5 , LMOTS_SHA256_N32_W2) },
    { WC_LMS_PARM_L3_H5_W4 , "LMS/HSS L3_H5_W4" ,
      LMS_PARAMS(3,  5, 4, 2, LMS_SHA256_M32_H5 , LMOTS_SHA256_N32_W4) },
    { WC_LMS_PARM_L3_H5_W8 , "LMS/HSS L3_H5_W8" ,
      LMS_PARAMS(3,  5, 8, 3, LMS_SHA256_M32_H5 , LMOTS_SHA256_N32_W8) },
#if LMS_MAX_HEIGHT >= 10
    { WC_LMS_PARM_L3_H10_W4, "LMS/HSS L3_H10_W4",
      LMS_PARAMS(3, 10, 4, 2, LMS_SHA256_M32_H10, LMOTS_SHA256_N32_W4) },
#endif
#endif
#if LMS_MAX_LEVELS >= 4
    { WC_LMS_PARM_L4_H5_W8 , "LMS/HSS L4_H5_W8" ,
      LMS_PARAMS(4,  5, 8, 3, LMS_SHA256_M32_H5 , LMOTS_SHA256_N32_W8) },
#endif

    /* For when user sets L, H, W explicitly. */
    { WC_LMS_PARM_L1_H5_W1 , "LMS/HSS_L1_H5_W1" ,
      LMS_PARAMS(1,  5, 1, 1, LMS_SHA256_M32_H5 , LMOTS_SHA256_N32_W1) },
    { WC_LMS_PARM_L1_H5_W2 , "LMS/HSS_L1_H5_W2" ,
      LMS_PARAMS(1,  5, 2, 1, LMS_SHA256_M32_H5 , LMOTS_SHA256_N32_W2) },
    { WC_LMS_PARM_L1_H5_W4 , "LMS/HSS_L1_H5_W4" ,
      LMS_PARAMS(1,  5, 4, 2, LMS_SHA256_M32_H5 , LMOTS_SHA256_N32_W4) },
    { WC_LMS_PARM_L1_H5_W8 , "LMS/HSS_L1_H5_W8" ,
      LMS_PARAMS(1,  5, 8, 3, LMS_SHA256_M32_H5 , LMOTS_SHA256_N32_W8) },
#if LMS_MAX_HEIGHT >= 10
    { WC_LMS_PARM_L1_H10_W2 , "LMS/HSS_L1_H10_W2",
      LMS_PARAMS(1, 10, 2, 1, LMS_SHA256_M32_H10, LMOTS_SHA256_N32_W2) },
    { WC_LMS_PARM_L1_H10_W4 , "LMS/HSS_L1_H10_W4",
      LMS_PARAMS(1, 10, 4, 2, LMS_SHA256_M32_H10, LMOTS_SHA256_N32_W4) },
    { WC_LMS_PARM_L1_H10_W8 , "LMS/HSS_L1_H10_W8",
      LMS_PARAMS(1, 10, 8, 3, LMS_SHA256_M32_H10, LMOTS_SHA256_N32_W8) },
#endif
#if LMS_MAX_HEIGHT >= 15
    { WC_LMS_PARM_L1_H15_W8 , "LMS/HSS L1_H15_W8",
      LMS_PARAMS(1, 15, 8, 3, LMS_SHA256_M32_H15, LMOTS_SHA256_N32_W8) },
#endif
#if LMS_MAX_HEIGHT >= 20
    { WC_LMS_PARM_L1_H20_W2 , "LMS/HSS_L1_H20_W2",
      LMS_PARAMS(1, 20, 2, 1, LMS_SHA256_M32_H20, LMOTS_SHA256_N32_W2) },
    { WC_LMS_PARM_L1_H20_W4 , "LMS/HSS_L1_H20_W4",
      LMS_PARAMS(1, 20, 4, 2, LMS_SHA256_M32_H20, LMOTS_SHA256_N32_W4) },
    { WC_LMS_PARM_L1_H20_W8 , "LMS/HSS_L1_H20_W8",
      LMS_PARAMS(1, 20, 8, 3, LMS_SHA256_M32_H20, LMOTS_SHA256_N32_W8) },
#endif
#if LMS_MAX_LEVELS >= 2
    { WC_LMS_PARM_L2_H5_W2 , "LMS/HSS_L2_H5_W2" ,
      LMS_PARAMS(2,  5, 2, 1, LMS_SHA256_M32_H5 , LMOTS_SHA256_N32_W2) },
    { WC_LMS_PARM_L2_H5_W4 , "LMS/HSS_L2_H5_W4" ,
      LMS_PARAMS(2,  5, 4, 2, LMS_SHA256_M32_H5 , LMOTS_SHA256_N32_W4) },
    { WC_LMS_PARM_L2_H5_W8 , "LMS/HSS_L2_H5_W8" ,
      LMS_PARAMS(2,  5, 8, 3, LMS_SHA256_M32_H5 , LMOTS_SHA256_N32_W8) },
#if LMS_MAX_HEIGHT >= 15
    { WC_LMS_PARM_L2_H15_W2 , "LMS/HSS_L2_H15_W2",
      LMS_PARAMS(2, 15, 2, 1, LMS_SHA256_M32_H15, LMOTS_SHA256_N32_W2) },
    { WC_LMS_PARM_L2_H15_W4 , "LMS/HSS_L2_H15_W4",
      LMS_PARAMS(2, 15, 4, 2, LMS_SHA256_M32_H15, LMOTS_SHA256_N32_W4) },
    { WC_LMS_PARM_L2_H15_W8 , "LMS/HSS_L2_H15_W8",
      LMS_PARAMS(2, 15, 8, 3, LMS_SHA256_M32_H15, LMOTS_SHA256_N32_W8) },
#endif
#if LMS_MAX_HEIGHT >= 20
    { WC_LMS_PARM_L2_H20_W2 , "LMS/HSS_L2_H20_W2",
      LMS_PARAMS(2, 20, 2, 1, LMS_SHA256_M32_H20, LMOTS_SHA256_N32_W2) },
    { WC_LMS_PARM_L2_H20_W4 , "LMS/HSS_L2_H20_W4",
      LMS_PARAMS(2, 20, 4, 2, LMS_SHA256_M32_H20, LMOTS_SHA256_N32_W4) },
    { WC_LMS_PARM_L2_H20_W8 , "LMS/HSS_L2_H20_W8",
      LMS_PARAMS(2, 20, 8, 3, LMS_SHA256_M32_H20, LMOTS_SHA256_N32_W8) },
#endif
#endif
#if LMS_MAX_LEVELS >= 3
#if LMS_MAX_HEIGHT >= 10
    { WC_LMS_PARM_L3_H10_W8 , "LMS/HSS L3_H10_W8",
      LMS_PARAMS(3, 10, 8, 3, LMS_SHA256_M32_H10, LMOTS_SHA256_N32_W8) },
#endif
#endif
#if LMS_MAX_LEVELS >= 4
    { WC_LMS_PARM_L4_H5_W2 , "LMS/HSS L4_H5_W2" ,
      LMS_PARAMS(4,  5, 2, 1, LMS_SHA256_M32_H5 , LMOTS_SHA256_N32_W2) },
    { WC_LMS_PARM_L4_H5_W4 , "LMS/HSS L4_H5_W4" ,
      LMS_PARAMS(4,  5, 4, 2, LMS_SHA256_M32_H5 , LMOTS_SHA256_N32_W4) },
#if LMS_MAX_HEIGHT >= 10
    { WC_LMS_PARM_L4_H10_W4 , "LMS/HSS L4_H10_W4",
      LMS_PARAMS(4, 10, 4, 2, LMS_SHA256_M32_H10, LMOTS_SHA256_N32_W4) },
    { WC_LMS_PARM_L4_H10_W8 , "LMS/HSS L4_H10_W8",
      LMS_PARAMS(4, 10, 8, 3, LMS_SHA256_M32_H10, LMOTS_SHA256_N32_W8) },
#endif
#endif
};
/* Number of parameter sets supported. */
#define WC_LMS_MAP_LEN      ((int)(sizeof(wc_lms_map) / sizeof(*wc_lms_map)))

/* Initialize LMS key.
 *
 * Call this before setting the params of an LMS key.
 *
 * @param [out] key    LMS key to initialize.
 * @param [in]  heap   Heap hint.
 * @param [in]  devId  Device identifier.
 *                     Use INVALID_DEVID when not using a device.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key is NULL.
 */
int wc_LmsKey_Init(LmsKey* key, void* heap, int devId)
{
    int ret = 0;

    (void)heap;
    (void)devId;

    /* Validate parameters. */
    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    if (ret == 0) {
        /* Zeroize the key data. */
        ForceZero(key, sizeof(LmsKey));

    #ifndef WOLFSSL_LMS_VERIFY_ONLY
        /* Initialize other fields. */
        key->write_private_key = NULL;
        key->read_private_key = NULL;
        key->context = NULL;
        key->heap = heap;
    #endif
    #ifdef WOLF_CRYPTO_CB
        key->devId = devId;
    #endif
        /* Start in initialized state. */
        key->state = WC_LMS_STATE_INITED;
    }

    return ret;
}

/* Get the string representation of the LMS parameter set.
 *
 * @param [in] lmsParm  LMS parameter set identifier.
 * @return  String representing LMS parameter set on success.
 * @return  NULL when parameter set not supported.
 */
const char* wc_LmsKey_ParmToStr(enum wc_LmsParm lmsParm)
{
    const char* str = NULL;
    int i;

    /* Search through table for matching numeric identifier. */
    for (i = 0; i < WC_LMS_MAP_LEN; i++) {
        if (lmsParm == wc_lms_map[i].id) {
            /* Get string corresponding to numeric identifier. */
            str = wc_lms_map[i].str;
            break;
        }
    }

    /* Return the string or NULL. */
    return str;
}

/* Set the wc_LmsParm of an LMS key.
 *
 * Use this if you wish to set a key with a predefined parameter set,
 * such as WC_LMS_PARM_L2_H10_W8.
 *
 * Key must be inited before calling this.
 *
 * @param [in, out] key      LMS key to set parameters on.
 * @param [in]      lmsParm  Identifier of parameters.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key is NULL.
 * @return  BAD_FUNC_ARG when parameters not supported.
 */
int wc_LmsKey_SetLmsParm(LmsKey* key, enum wc_LmsParm lmsParm)
{
    int ret = 0;

    /* Validate parameters. */
    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }

    /* Check state is valid. */
    if ((ret == 0) && (key->state != WC_LMS_STATE_INITED)) {
        WOLFSSL_MSG("error: LmsKey needs init");
        ret = BAD_STATE_E;
    }

    if (ret == 0) {
        int i;

        ret = BAD_FUNC_ARG;
        /* Search through table for matching numeric identifier. */
        for (i = 0; i < WC_LMS_MAP_LEN; i++) {
            if (lmsParm == wc_lms_map[i].id) {
                /* Set the parameters into the key. */
                key->params = &wc_lms_map[i].params;
                ret = 0;
                break;
            }
        }
    }

    if (ret == 0) {
        /* Move the state to params set.
         * Key is ready for MakeKey or Reload. */
        key->state = WC_LMS_STATE_PARMSET;
    }

    return ret;
}

/* Set the parameters of an LMS key.
 *
 * Use this if you wish to set specific parameters not found in the
 * wc_LmsParm predefined sets. See comments in lms.h for allowed
 * parameters.
 *
 * Key must be inited before calling this.
 *
 * @param [in, out] key         LMS key to set parameters on.
 * @param [in]      levels      Number of tree levels.
 * @param [in]      height      Height of each tree.
 * @param [in]      winternitz  Width or Winternitz coefficient.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key is NULL.
 * @return  BAD_FUNC_ARG when parameters not supported.
 * */
int wc_LmsKey_SetParameters(LmsKey* key, int levels, int height,
    int winternitz)
{
    int ret = 0;

    /* Validate parameters. */
    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }

    /* Check state is valid. */
    if ((ret == 0) && (key->state != WC_LMS_STATE_INITED)) {
        WOLFSSL_MSG("error: LmsKey needs init");
        ret = BAD_STATE_E;
    }

    if (ret == 0) {
        int i;

        ret = BAD_FUNC_ARG;
        /* Search through table for matching levels, height and width. */
        for (i = 0; i < WC_LMS_MAP_LEN; i++) {
            if ((levels == wc_lms_map[i].params.levels) &&
                    (height == wc_lms_map[i].params.height) &&
                    (winternitz == wc_lms_map[i].params.width)) {
                /* Set the parameters into the key. */
                key->params = &wc_lms_map[i].params;
                ret = 0;
                break;
            }
        }
    }

    if (ret == 0) {
        /* Move the state to params set.
         * Key is ready for MakeKey or Reload. */
        key->state = WC_LMS_STATE_PARMSET;
    }

    return ret;
}

/* Get the parameters of an LMS key.
 *
 * Key must be inited and parameters set before calling this.
 *
 * @param [in]  key         LMS key.
 * @param [out] levels      Number of levels of trees.
 * @param [out] height      Height of the trees.
 * @param [out] winternitz  Winternitz width.
 * Returns 0 on success.
 * */
int wc_LmsKey_GetParameters(const LmsKey* key, int* levels, int* height,
    int* winternitz)
{
    int ret = 0;

    /* Validate parameters. */
    if ((key == NULL) || (levels == NULL) || (height == NULL) ||
            (winternitz == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    /* Validate the parameters are available. */
    if ((ret == 0) && (key->params == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Set the levels, height and Winternitz width from parameters. */
        *levels = key->params->levels;
        *height = key->params->height;
        *winternitz = key->params->width;
    }

    return ret;
}

/* Frees the LMS key from memory.
 *
 * This does not affect the private key saved to non-volatile storage.
 *
 * @param [in, out] key  LMS key to free.
 */
void wc_LmsKey_Free(LmsKey* key)
{
    if (key != NULL) {
    #ifndef WOLFSSL_LMS_VERIFY_ONLY
        if (key->priv_data != NULL) {
            const LmsParams* params = key->params;

            ForceZero(key->priv_data, LMS_PRIV_DATA_LEN(params->levels,
                params->height, params->p, params->rootLevels,
                params->cacheBits));

            XFREE(key->priv_data, key->heap, DYNAMIC_TYPE_LMS);
        }
    #endif

        ForceZero(key, sizeof(LmsKey));

        key->state = WC_LMS_STATE_FREED;
    }
}

#ifndef WOLFSSL_LMS_VERIFY_ONLY
/* Set the write private key callback to the LMS key structure.
 *
 * The callback must be able to write/update the private key to
 * non-volatile storage.
 *
 * @param [in, out] key       LMS key.
 * @param [in]      write_cb  Callback function that stores private key.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key or write_cb is NULL.
 * @return  BAD_STATE_E when key state is invalid.
 */
int wc_LmsKey_SetWriteCb(LmsKey* key, wc_lms_write_private_key_cb write_cb)
{
    int ret = 0;

    /* Validate parameters. */
    if ((key == NULL) || (write_cb == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    /* Changing the write callback of an already working key is forbidden. */
    if ((ret == 0) && (key->state == WC_LMS_STATE_OK)) {
        WOLFSSL_MSG("error: wc_LmsKey_SetWriteCb: key in use");
        ret = BAD_STATE_E;
    }

    if (ret == 0) {
        /* Set the callback into the key. */
        key->write_private_key = write_cb;
    }

    return ret;
}

/* Set the read private key callback to the LMS key structure.
 *
 * The callback must be able to read the private key from
 * non-volatile storage.
 *
 * @param [in, out] key      LMS key.
 * @param [in]      read_cb  Callback function that loads private key.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key or read_cb is NULL.
 * @return  BAD_STATE_E when key state is invalid.
 * */
int wc_LmsKey_SetReadCb(LmsKey* key, wc_lms_read_private_key_cb read_cb)
{
    int ret = 0;

    /* Validate parameters. */
    if ((key == NULL) || (read_cb == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    /* Changing the read callback of an already working key is forbidden. */
    if ((ret == 0) && (key->state == WC_LMS_STATE_OK)) {
        WOLFSSL_MSG("error: wc_LmsKey_SetReadCb: key in use");
        ret = BAD_STATE_E;
    }

    if (ret == 0) {
        /* Set the callback into the key. */
        key->read_private_key = read_cb;
    }

    return ret;
}

/* Sets the context to be used by write and read callbacks.
 *
 * E.g. this could be a filename if the callbacks write/read to file.
 *
 * @param [in, out] key      LMS key.
 * @param [in]      context  Pointer to data for read/write callbacks.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key or context is NULL.
 * @return  BAD_STATE_E when key state is invalid.
 * */
int wc_LmsKey_SetContext(LmsKey* key, void* context)
{
    int ret = 0;

    /* Validate parameters. */
    if ((key == NULL) || (context == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    /* Setting context of an already working key is forbidden. */
    if ((ret == 0) && (key->state == WC_LMS_STATE_OK)) {
        WOLFSSL_MSG("error: wc_LmsKey_SetContext: key in use");
        ret = BAD_STATE_E;
    }

    if (ret == 0) {
        /* Set the callback context into the key. */
        key->context = context;
    }

    return ret;
}

/* Make the LMS private/public key pair. The key must have its parameters
 * set before calling this.
 *
 * Write/read callbacks, and context data, must be set prior.
 * Key must have parameters set.
 *
 * @param [in, out] key   LMS key.
 * @param [in]      rng   Random number generator.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key or rng is NULL.
 * @return  BAD_STATE_E when key is in an invalid state.
 * @return  BAD_FUNC_ARG when write callback or callback context not set.
 * @return  BAD_STATE_E when no more signatures can be created.
 */
int wc_LmsKey_MakeKey(LmsKey* key, WC_RNG* rng)
{
    int ret = 0;

    /* Validate parameters. */
    if ((key == NULL) || (rng == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    /* Check state. */
    if ((ret == 0) && (key->state != WC_LMS_STATE_PARMSET)) {
        WOLFSSL_MSG("error: LmsKey not ready for generation");
        ret = BAD_STATE_E;
    }
    /* Check write callback set. */
    if ((ret == 0) && (key->write_private_key == NULL)) {
        WOLFSSL_MSG("error: LmsKey write callback is not set");
        ret = BAD_FUNC_ARG;
    }
    /* Check callback context set. */
    if ((ret == 0) && (key->context == NULL)) {
        WOLFSSL_MSG("error: LmsKey context is not set");
        ret = BAD_FUNC_ARG;
    }

    if ((ret == 0) && (key->priv_data == NULL)) {
        const LmsParams* params = key->params;

        /* Allocate memory for the private key data. */
        key->priv_data = (byte *)XMALLOC(LMS_PRIV_DATA_LEN(params->levels,
            params->height, params->p, params->rootLevels, params->cacheBits),
            key->heap, DYNAMIC_TYPE_LMS);
        /* Check pointer is valid. */
        if (key->priv_data == NULL) {
            ret = MEMORY_E;
        }
    }
    if (ret == 0) {
    #ifdef WOLFSSL_SMALL_STACK
        LmsState* state;
    #else
        LmsState state[1];
    #endif

    #ifdef WOLFSSL_SMALL_STACK
        /* Allocate memory for working state. */
        state = XMALLOC(sizeof(LmsState), NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (state == NULL) {
            ret = MEMORY_E;
        }
        if (ret == 0)
    #endif
        {
            /* Initialize working state for use. */
            ret = wc_lmskey_state_init(state, key->params);
            if (ret == 0) {
                /* Make the HSS key. */
                ret = wc_hss_make_key(state, rng, key->priv_raw, &key->priv,
                    key->priv_data, key->pub);
                wc_lmskey_state_free(state);
            }
            ForceZero(state, sizeof(LmsState));
        #ifdef WOLFSSL_SMALL_STACK
            XFREE(state, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        #endif
        }
    }
    if (ret == 0) {
        /* Write private key to storage. */
        int rv = key->write_private_key(key->priv_raw, HSS_PRIVATE_KEY_LEN,
            key->context);
        if (rv != WC_LMS_RC_SAVED_TO_NV_MEMORY) {
            ret = IO_FAILED_E;
        }
    }

    /* This should not happen, but check whether signatures can be created. */
    if ((ret == 0) && (wc_LmsKey_SigsLeft(key) == 0)) {
        WOLFSSL_MSG("error: generated LMS key signatures exhausted");
        key->state = WC_LMS_STATE_NOSIGS;
        ret = BAD_STATE_E;
    }

    if (ret == 0) {
        /* Update state. */
        key->state = WC_LMS_STATE_OK;
    }

    return ret;
}

/* Reload a key that has been prepared with the appropriate params and
 * data. Use this if you wish to resume signing with an existing key.
 *
 * Write/read callbacks, and context data, must be set prior.
 * Key must have parameters set.
 *
 * @param [in, out] key  LMS key.
 *
 * Returns 0 on success. */
int wc_LmsKey_Reload(LmsKey* key)
{
    int ret = 0;

    /* Validate parameter. */
    if (key == NULL) {
        ret = BAD_FUNC_ARG;
    }
    /* Check state. */
    if ((ret == 0) && (key->state != WC_LMS_STATE_PARMSET)) {
        WOLFSSL_MSG("error: LmsKey not ready for reload");
        ret = BAD_STATE_E;
    }
    /* Check read callback present. */
    if ((ret == 0) && (key->read_private_key == NULL)) {
        WOLFSSL_MSG("error: LmsKey read callback is not set");
        ret = BAD_FUNC_ARG;
    }
    /* Check context for callback set */
    if ((ret == 0) && (key->context == NULL)) {
        WOLFSSL_MSG("error: LmsKey context is not set");
        ret = BAD_FUNC_ARG;
    }

    if ((ret == 0) && (key->priv_data == NULL)) {
        const LmsParams* params = key->params;

        /* Allocate memory for the private key data. */
        key->priv_data = (byte *)XMALLOC(LMS_PRIV_DATA_LEN(params->levels,
            params->height, params->p, params->rootLevels, params->cacheBits),
            key->heap, DYNAMIC_TYPE_LMS);
        /* Check pointer is valid. */
        if (key->priv_data == NULL) {
            ret = MEMORY_E;
        }
    }
    if (ret == 0) {
        /* Load private key. */
        int rv = key->read_private_key(key->priv_raw, HSS_PRIVATE_KEY_LEN,
            key->context);
        if (rv != WC_LMS_RC_READ_TO_MEMORY) {
            ret = IO_FAILED_E;
        }
    }

    /* Double check the key actually has signatures left. */
    if ((ret == 0) && (wc_LmsKey_SigsLeft(key) == 0)) {
        WOLFSSL_MSG("error: reloaded LMS key signatures exhausted");
        key->state = WC_LMS_STATE_NOSIGS;
        ret = BAD_STATE_E;
    }

    if (ret == 0) {
    #ifdef WOLFSSL_SMALL_STACK
        LmsState* state;
    #else
        LmsState state[1];
    #endif

    #ifdef WOLFSSL_SMALL_STACK
        /* Allocate memory for working state. */
        state = XMALLOC(sizeof(LmsState), NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (state == NULL) {
            ret = MEMORY_E;
        }
        if (ret == 0)
    #endif
        {
            /* Initialize working state for use. */
            ret = wc_lmskey_state_init(state, key->params);
            if (ret == 0) {
                /* Reload the key ready for signing. */
                ret = wc_hss_reload_key(state, key->priv_raw, &key->priv,
                    key->priv_data, NULL);
            }
            ForceZero(state, sizeof(LmsState));
        #ifdef WOLFSSL_SMALL_STACK
            XFREE(state, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        #endif
        }
    }

    if (ret == 0) {
        /* Update state. */
        key->state = WC_LMS_STATE_OK;
    }

    return ret;
}

/* Get the private key length based on parameter set of key.
 *
 * @param [in]  key  LMS key.
 * @param [out] len  Length of private key.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key or len is NULL or parameters not set.
 */
int wc_LmsKey_GetPrivLen(const LmsKey* key, word32* len)
{
    int ret = 0;

    /* Validate parameters. */
    if ((key == NULL) || (len == NULL) || (key->params == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Return private key length from parameter set. */
        *len = HSS_PRIVATE_KEY_LEN;
    }

    return ret;
}

/* Sign a message.
 *
 * @param [in, out] key    LMS key to sign with.
 * @param [out]     sig    Signature data. Buffer must be big enough to hold
 *                         signature data.
 * @param [out]     sigSz  Length of signature data.
 * @param [in]      msg    Message to sign.
 * @param [in]      msgSz  Length of message in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key, sig, sigSz or msg is NULL.
 * @return  BAD_FUNC_ARG when msgSz is not greater than 0.
 */
int wc_LmsKey_Sign(LmsKey* key, byte* sig, word32* sigSz, const byte* msg,
    int msgSz)
{
    int ret = 0;

    /* Validate parameters. */
    if ((key == NULL) || (sig == NULL) || (sigSz == NULL) || (msg == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    if ((ret == 0) && (msgSz <= 0)) {
        ret = BAD_FUNC_ARG;
    }
    /* Check state. */
    if ((ret == 0) && (key->state == WC_LMS_STATE_NOSIGS)) {
        WOLFSSL_MSG("error: LMS signatures exhausted");
        ret = BAD_STATE_E;
    }
    if ((ret == 0) && (key->state != WC_LMS_STATE_OK)) {
       /* The key had an error the last time it was used, and we
        * can't guarantee its state. */
        WOLFSSL_MSG("error: can't sign, LMS key not in good state");
        ret = BAD_STATE_E;
    }

    if (ret == 0) {
    #ifdef WOLFSSL_SMALL_STACK
        LmsState* state;
    #else
        LmsState state[1];
    #endif

    #ifdef WOLFSSL_SMALL_STACK
        /* Allocate memory for working state. */
        state = XMALLOC(sizeof(LmsState), NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (state == NULL) {
            ret = MEMORY_E;
        }
        if (ret == 0)
    #endif
        {
            /* Initialize working state for use. */
            ret = wc_lmskey_state_init(state, key->params);
            if (ret == 0) {
                /* Sign message. */
                ret = wc_hss_sign(state, key->priv_raw, &key->priv,
                    key->priv_data, msg, msgSz, sig);
                wc_lmskey_state_free(state);
            }
            ForceZero(state, sizeof(LmsState));
        #ifdef WOLFSSL_SMALL_STACK
            XFREE(state, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        #endif
        }
    }
    if (ret == 0) {
        *sigSz = (word32)key->params->sig_len;
    }
    if (ret == 0) {
        /* Write private key to storage. */
        int rv = key->write_private_key(key->priv_raw, HSS_PRIVATE_KEY_LEN,
            key->context);
        if (rv != WC_LMS_RC_SAVED_TO_NV_MEMORY) {
            ret = IO_FAILED_E;
        }
    }

    return ret;
}

/* Returns whether signatures can be created with key.
 *
 * @param [in]  key  LMS key.
 *
 * @return  1 if there are signatures remaining.
 * @return  0 if available signatures are exhausted.
 */
int wc_LmsKey_SigsLeft(LmsKey* key)
{
    int ret = 0;

    /* NULL keys have no signatures remaining. */
    if (key != NULL) {
        ret = wc_hss_sigsleft(key->params, key->priv_raw);
    }

    return ret;
}

#endif /* ifndef WOLFSSL_LMS_VERIFY_ONLY*/

/* Get the public key length based on parameter set of key.
 *
 * @param [in]  key  LMS key.
 * @param [out] len  Length of public key.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key or len is NULL or parameters not set.
 */
int wc_LmsKey_GetPubLen(const LmsKey* key, word32* len)
{
    int ret = 0;

    /* Validate parameters */
    if ((key == NULL) || (len == NULL) || (key->params == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        *len = HSS_PUBLIC_KEY_LEN;
    }

    return ret;
}

/* Export a generated public key and parameter set from one LmsKey
 * to another. Use this to prepare a signature verification LmsKey
 * that is pub only.
 *
 * Though the public key is all that is used to verify signatures,
 * the parameter set is needed to calculate the signature length
 * before hand.
 *
 * @param [out] keyDst  LMS key to copy into.
 * @param [in]  keySrc  LMS key to copy.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when keyDst or keySrc is NULL.
 */
int wc_LmsKey_ExportPub(LmsKey* keyDst, const LmsKey* keySrc)
{
    int ret = 0;

    if ((keyDst == NULL) || (keySrc == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        ForceZero(keyDst, sizeof(LmsKey));

        keyDst->params = keySrc->params;
        XMEMCPY(keyDst->pub, keySrc->pub, sizeof(keySrc->pub));

        /* Mark this key as verify only, to prevent misuse. */
        keyDst->state = WC_LMS_STATE_VERIFYONLY;
    }

    return ret;
}

/* Exports the raw LMS public key buffer from key to out buffer.
 * The out buffer should be large enough to hold the public key, and
 * outLen should indicate the size of the buffer.
 *
 * Call wc_LmsKey_GetPubLen beforehand to determine pubLen.
 *
 * @param [in]      key     LMS key.
 * @param [out]     out     Buffer to hold encoded public key.
 * @param [in, out] outLen  On in, length of out in bytes.
 *                          On out, the length of the public key in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key, out or outLen is NULL.
 * @return  BUFFER_E when outLen is too small to hold encoded public key.
 */
int wc_LmsKey_ExportPubRaw(const LmsKey* key, byte* out, word32* outLen)
{
    int ret = 0;

    /* Validate parameters. */
    if ((key == NULL) || (out == NULL) || (outLen == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    /* Check size of out is sufficient. */
    if ((ret == 0) && (*outLen < HSS_PUBLIC_KEY_LEN)) {
        ret = BUFFER_E;
    }

    if (ret == 0) {
        /* Return encoded public key. */
        XMEMCPY(out, key->pub, HSS_PUBLIC_KEY_LEN);
        *outLen = HSS_PUBLIC_KEY_LEN;
    }

    return ret;
}

/* Imports a raw public key buffer from in array to LmsKey key.
 *
 * The LMS parameters must be set first with wc_LmsKey_SetLmsParm or
 * wc_LmsKey_SetParameters, and inLen must match the length returned
 * by wc_LmsKey_GetPubLen.
 *
 * Call wc_LmsKey_GetPubLen beforehand to determine pubLen.
 *
 * @param [in, out] key    LMS key to put public key in.
 * @param [in]      in     Buffer holding encoded public key.
 * @param [in]      inLen  Length of encoded public key in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key or in is NULL.
 * @return  BUFFER_E when inLen does not match public key length by parameters.
 */
int wc_LmsKey_ImportPubRaw(LmsKey* key, const byte* in, word32 inLen)
{
    int ret = 0;

    /* Validate parameters. */
    if ((key == NULL) || (in == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    if ((ret == 0) && (inLen != HSS_PUBLIC_KEY_LEN)) {
        /* Something inconsistent. Parameters weren't set, or input
         * pub key is wrong.*/
        return BUFFER_E;
    }

    if (ret == 0) {
        XMEMCPY(key->pub, in, inLen);

        key->state = WC_LMS_STATE_VERIFYONLY;
    }

    return ret;
}

/* Given a levels, height, winternitz parameter set, determine
 * the signature length.
 *
 * Call this before wc_LmsKey_Sign so you know the length of
 * the required signature buffer.
 *
 * @param [in]  key  LMS key.
 * @param [out] len  Length of a signature in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when key or len is NULL.
 */
int wc_LmsKey_GetSigLen(const LmsKey* key, word32* len)
{
    int ret = 0;

    /* Validate parameters. */
    if ((key == NULL) || (len == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        *len = key->params->sig_len;
    }

    return ret;
}

/* Verify the signature of the message with public key.
 *
 * @param [in] key    LMS key.
 * @param [in] sig    Signature to verify.
 * @param [in] sigSz  Size of signature in bytes.
 * @param [in] msg    Message to verify.
 * @param [in] msgSz  Length of the message in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a key, sig or msg is NULL.
 * @return  SIG_VERIFY_E when signature did not verify message.
 * @return  BAD_STATE_E when wrong state for operation.
 * @return  BUFFER_E when sigSz is invalid for parameters.
 */
int wc_LmsKey_Verify(LmsKey* key, const byte* sig, word32 sigSz,
    const byte* msg, int msgSz)
{
    int ret = 0;

    /* Validate parameters. */
    if ((key == NULL) || (sig == NULL) || (msg == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    /* Check state. */
    if ((ret == 0) && (key->state != WC_LMS_STATE_OK) &&
            (key->state != WC_LMS_STATE_VERIFYONLY)) {
        /* LMS key not ready for verification. Param str must be
         * set first, and Reload() called. */
        WOLFSSL_MSG("error: LMS key not ready for verification");
        ret = BAD_STATE_E;
    }
    /* Check signature length. */
    if ((ret == 0) && (sigSz != key->params->sig_len)) {
        ret = BUFFER_E;
    }

    if (ret == 0) {
    #ifdef WOLFSSL_SMALL_STACK
        LmsState* state;
    #else
        LmsState state[1];
    #endif

    #ifdef WOLFSSL_SMALL_STACK
        /* Allocate memory for working state. */
        state = XMALLOC(sizeof(LmsState), NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (state == NULL) {
            ret = MEMORY_E;
        }
        if (ret == 0)
    #endif
        {
            /* Initialize working state for use. */
            ret = wc_lmskey_state_init(state, key->params);
            if (ret == 0) {
                /* Verify signature of message with public key. */
                ret = wc_hss_verify(state, key->pub, msg, msgSz, sig);
                wc_lmskey_state_free(state);
            }
            ForceZero(state, sizeof(LmsState));
        #ifdef WOLFSSL_SMALL_STACK
            XFREE(state, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        #endif
        }
    }

    return ret;
}

#endif /* WOLFSSL_HAVE_LMS && WOLFSSL_WC_LMS */
