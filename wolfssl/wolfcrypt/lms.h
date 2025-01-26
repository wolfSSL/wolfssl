/* lms.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

/*!
    \file wolfssl/wolfcrypt/lms.h
 */

#ifndef WOLF_CRYPT_LMS_H
#define WOLF_CRYPT_LMS_H

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/random.h>

#ifdef WOLFSSL_HAVE_LMS

typedef struct LmsKey LmsKey;

/* Private key write and read callbacks. */
typedef int (*wc_lms_write_private_key_cb)(const byte * priv, word32 privSz, void *context);
typedef int (*wc_lms_read_private_key_cb)(byte * priv, word32 privSz, void *context);

/* Return codes returned by private key callbacks. */
enum wc_LmsRc {
  WC_LMS_RC_NONE,
  WC_LMS_RC_BAD_ARG,            /* Bad arg in read or write callback. */
  WC_LMS_RC_WRITE_FAIL,         /* Write or update private key failed. */
  WC_LMS_RC_READ_FAIL,          /* Read private key failed. */
  WC_LMS_RC_SAVED_TO_NV_MEMORY, /* Wrote private key to nonvolatile storage. */
  WC_LMS_RC_READ_TO_MEMORY      /* Read private key from storage. */
};

/* LMS/HSS signatures are defined by 3 parameters:
 *   levels: number of levels of Merkle trees.
 *   height: height of an individual Merkle tree.
 *   winternitz: number of bits from hash used in a Winternitz chain.
 *
 * The acceptable parameter values are those in RFC8554:
 *   levels = {1..8}
 *   height = {5, 10, 15, 20, 25}
 *   winternitz = {1, 2, 4, 8}
 *
 * The number of available signatures is:
 *   N = 2 ** (levels * height)
 *
 * Signature sizes are determined by levels and winternitz
 * parameters primarily, and height to a lesser extent:
 *   - Larger levels values increase signature size significantly.
 *   - Larger height values increase signature size moderately.
 *   - Larger winternitz values will reduce the signature size, at
 *     the expense of longer key generation and sign/verify times.
 *
 * Key generation time is strongly determined by the height of
 * the first level tree. A 3 level, 5 height tree is much faster
 * than 1 level, 15 height at initial key gen, even if the number
 * of available signatures is the same.
 * */

/* Predefined LMS/HSS parameter sets for convenience.
 *
 * Not predefining many sets with Winternitz=1, because the signatures
 * will be large. */
enum wc_LmsParm {
#ifndef WOLFSSL_NO_LMS_SHA256_256
    WC_LMS_PARM_NONE = 0,
    WC_LMS_PARM_L1_H5_W1 = 1,
    WC_LMS_PARM_L1_H5_W2 = 2,
    WC_LMS_PARM_L1_H5_W4 = 3,
    WC_LMS_PARM_L1_H5_W8 = 4,
    WC_LMS_PARM_L1_H10_W2 = 5,
    WC_LMS_PARM_L1_H10_W4 = 6,
    WC_LMS_PARM_L1_H10_W8 = 7,
    WC_LMS_PARM_L1_H15_W2 = 8,
    WC_LMS_PARM_L1_H15_W4 = 9,
    WC_LMS_PARM_L1_H15_W8 = 10,
    WC_LMS_PARM_L1_H20_W2 = 11,
    WC_LMS_PARM_L1_H20_W4 = 12,
    WC_LMS_PARM_L1_H20_W8 = 13,
    WC_LMS_PARM_L2_H5_W2 = 14,
    WC_LMS_PARM_L2_H5_W4 = 15,
    WC_LMS_PARM_L2_H5_W8 = 16,
    WC_LMS_PARM_L2_H10_W2 = 17,
    WC_LMS_PARM_L2_H10_W4 = 18,
    WC_LMS_PARM_L2_H10_W8 = 19,
    WC_LMS_PARM_L2_H15_W2 = 20,
    WC_LMS_PARM_L2_H15_W4 = 21,
    WC_LMS_PARM_L2_H15_W8 = 22,
    WC_LMS_PARM_L2_H20_W2 = 23,
    WC_LMS_PARM_L2_H20_W4 = 24,
    WC_LMS_PARM_L2_H20_W8 = 25,
    WC_LMS_PARM_L3_H5_W2 = 26,
    WC_LMS_PARM_L3_H5_W4 = 27,
    WC_LMS_PARM_L3_H5_W8 = 28,
    WC_LMS_PARM_L3_H10_W4 = 29,
    WC_LMS_PARM_L3_H10_W8 = 30,
    WC_LMS_PARM_L4_H5_W2 = 31,
    WC_LMS_PARM_L4_H5_W4 = 32,
    WC_LMS_PARM_L4_H5_W8 = 33,
    WC_LMS_PARM_L4_H10_W4 = 34,
    WC_LMS_PARM_L4_H10_W8 = 35,
#endif

#ifdef WOLFSSL_LMS_SHA256_192
    WC_LMS_PARM_SHA256_192_L1_H5_W1  = 36,
    WC_LMS_PARM_SHA256_192_L1_H5_W2  = 37,
    WC_LMS_PARM_SHA256_192_L1_H5_W4  = 38,
    WC_LMS_PARM_SHA256_192_L1_H5_W8  = 39,
    WC_LMS_PARM_SHA256_192_L1_H10_W2 = 40,
    WC_LMS_PARM_SHA256_192_L1_H10_W4 = 41,
    WC_LMS_PARM_SHA256_192_L1_H10_W8 = 42,
    WC_LMS_PARM_SHA256_192_L1_H15_W2 = 43,
    WC_LMS_PARM_SHA256_192_L1_H15_W4 = 44,
    WC_LMS_PARM_SHA256_192_L2_H10_W2 = 45,
    WC_LMS_PARM_SHA256_192_L2_H10_W4 = 46,
    WC_LMS_PARM_SHA256_192_L2_H10_W8 = 47,
    WC_LMS_PARM_SHA256_192_L3_H5_W2  = 48,
    WC_LMS_PARM_SHA256_192_L3_H5_W4  = 49,
    WC_LMS_PARM_SHA256_192_L3_H5_W8  = 50,
    WC_LMS_PARM_SHA256_192_L3_H10_W4 = 51,
    WC_LMS_PARM_SHA256_192_L4_H5_W8  = 52,
#endif
};

/* enum wc_LmsState is to help track the state of an LMS/HSS Key. */
enum wc_LmsState {
    WC_LMS_STATE_FREED,      /* Key has been freed from memory. */
    WC_LMS_STATE_INITED,     /* Key has been inited, ready to set params.*/
    WC_LMS_STATE_PARMSET,    /* Params are set, ready to MakeKey or Reload. */
    WC_LMS_STATE_OK,         /* Able to sign signatures and verify. */
    WC_LMS_STATE_VERIFYONLY, /* A public only LmsKey. */
    WC_LMS_STATE_BAD,        /* Can't guarantee key's state. */
    WC_LMS_STATE_NOSIGS      /* Signatures exhausted. */
};

#ifdef __cplusplus
    extern "C" {
#endif
WOLFSSL_API int  wc_LmsKey_Init(LmsKey * key, void * heap, int devId);
WOLFSSL_API int  wc_LmsKey_SetLmsParm(LmsKey * key, enum wc_LmsParm lmsParm);
WOLFSSL_API int  wc_LmsKey_SetParameters(LmsKey * key, int levels,
    int height, int winternitz);
WOLFSSL_API int  wc_LmsKey_GetParameters(const LmsKey * key, int * levels,
    int * height, int * winternitz);
#ifndef WOLFSSL_LMS_VERIFY_ONLY
WOLFSSL_API int  wc_LmsKey_SetWriteCb(LmsKey * key,
    wc_lms_write_private_key_cb write_cb);
WOLFSSL_API int  wc_LmsKey_SetReadCb(LmsKey * key,
    wc_lms_read_private_key_cb read_cb);
WOLFSSL_API int  wc_LmsKey_SetContext(LmsKey * key, void * context);
WOLFSSL_API int  wc_LmsKey_MakeKey(LmsKey * key, WC_RNG * rng);
WOLFSSL_API int  wc_LmsKey_Reload(LmsKey * key);
WOLFSSL_API int  wc_LmsKey_GetPrivLen(const LmsKey * key, word32 * len);
WOLFSSL_API int  wc_LmsKey_Sign(LmsKey * key, byte * sig, word32 * sigSz,
    const byte * msg, int msgSz);
WOLFSSL_API int  wc_LmsKey_SigsLeft(LmsKey * key);
#endif /* ifndef WOLFSSL_LMS_VERIFY_ONLY */
WOLFSSL_API void wc_LmsKey_Free(LmsKey * key);
WOLFSSL_API int  wc_LmsKey_GetSigLen(const LmsKey * key, word32 * len);
WOLFSSL_API int  wc_LmsKey_GetPubLen(const LmsKey * key, word32 * len);
WOLFSSL_API int  wc_LmsKey_ExportPub(LmsKey * keyDst, const LmsKey * keySrc);
WOLFSSL_API int  wc_LmsKey_ExportPubRaw(const LmsKey * key, byte * out,
    word32 * outLen);
WOLFSSL_API int  wc_LmsKey_ImportPubRaw(LmsKey * key, const byte * in,
    word32 inLen);
WOLFSSL_API int  wc_LmsKey_Verify(LmsKey * key, const byte * sig, word32 sigSz,
    const byte * msg, int msgSz);
WOLFSSL_API const char * wc_LmsKey_ParmToStr(enum wc_LmsParm lmsParm);
WOLFSSL_API const char * wc_LmsKey_RcToStr(enum wc_LmsRc lmsRc);
#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFSSL_HAVE_LMS */
#endif /* WOLF_CRYPT_LMS_H */
