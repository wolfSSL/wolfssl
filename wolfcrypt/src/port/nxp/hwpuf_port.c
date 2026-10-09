/* hwpuf_port.c
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


#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#if defined(WOLFSSL_NXP_HWPUF)

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/port/nxp/hwpuf_port.h>
#include "fsl_puf.h"

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/* PUF lifecycle:
 *   Provisioning (once per device):
 *     Init -> Enroll -> Deinit -> Init -> Start -> GenerateKey(s)
 *   Normal boot:
 *     Init -> Start -> GetKey(s)
 *   Enroll and Start are mutually exclusive within one Init session; the PUF
 *   must be re-initialized (Deinit/Init) after Enroll before Start, matching
 *   the NXP SDK PUF example flow. Zeroize wipes PUF state and must be
 *   followed by Deinit/Init before further use.
 */

#define HWPUF_KEY_SIZE_IS_VALID(keysz) \
    ((keysz) == 16 || (keysz) == 24 || (keysz) == 32)

typedef enum nxp_hwpuf_flag {
    NXP_HWPUF_FLAG_NONE     =    0,  /* Deinit() clears all flags */
    NXP_HWPUF_FLAG_INITED   = 0x01,  /* Init() called successfully */
    NXP_HWPUF_FLAG_ENROLLED = 0x02,  /* Enroll() called successfully */
    NXP_HWPUF_FLAG_READY    = 0x04,  /* Start() called successfully */
    WOLF_ENUM_DUMMY_LAST_ELEMENT(NXP_HWPUF_FLAG)
} nxp_hwpuf_flag;

typedef enum nxp_hwpuf_keytype {
    nxp_hwpuf_keytype_user = 0,
    nxp_hwpuf_keytype_intrinsic = 1,
    nxp_hwpuf_keytype_max = nxp_hwpuf_keytype_intrinsic
} nxp_hwpuf_keytype;

typedef struct nxp_hwpuf_ctx {
    word32 flags;
} nxp_hwpuf_ctx;

static nxp_hwpuf_ctx ctx;
static puf_config_t conf;

static int keyCodeCheck(const byte* keyCode, word32* keytype,
                        word32* keyidx, word32* keysize)
{
    *keytype = keyCode[0];
    *keyidx = keyCode[1];
    *keysize = keyCode[3] == 0 ? 512 : 8 * keyCode[3] ;

    if (*keytype > nxp_hwpuf_keytype_max)
        return 1;
    if (*keyidx > kPUF_KeyIndexMax)
        return 2;
    if ( !HWPUF_KEY_SIZE_IS_VALID(*keysize) )
        return 3;

    return 0;
}

/* Validate PUF state and key code, return key index and key size */
static int keyCodeParse(const byte* keyCode, word32 keyCodeSz,
                        word32* keyidx, word32* keysize)
{
    word32 keytype;

    if ((ctx.flags & NXP_HWPUF_FLAG_READY) == 0)
        return HWPUF_START_E;
    if (keyCode == NULL || keyCodeSz < PUF_MIN_KEY_CODE_SIZE)
        return BAD_FUNC_ARG;
    if (keyCodeCheck(keyCode, &keytype, keyidx, keysize) != 0)
        return BAD_FUNC_ARG;
    if (PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(*keysize) != keyCodeSz)
        return BAD_FUNC_ARG;

    return 0;
}

WOLFSSL_API int nxp_hwpuf_Init(void)
{
    WOLFSSL_ENTER("nxp_hwpuf_Init");

    if ((ctx.flags & NXP_HWPUF_FLAG_INITED) != 0)
        return 0;

    PUF_GetDefaultConfig(&conf);
    if (PUF_Init(PUF, &conf) != kStatus_Success) {
        PUF_Deinit(PUF, &conf);
        return HWPUF_INIT_E;
    }
    ctx.flags |= NXP_HWPUF_FLAG_INITED;
    return 0;
}

WOLFSSL_API int nxp_hwpuf_Deinit(void)
{
    WOLFSSL_ENTER("nxp_hwpuf_Deinit");

    PUF_Deinit(PUF, &conf);

    ctx.flags = 0;

    return 0;
}

WOLFSSL_API int nxp_hwpuf_Enroll(byte* actCode, word32 actCodeSz)
{
    int ret;

    WOLFSSL_ENTER("nxp_hwpuf_Enroll");

    if (actCode == NULL || actCodeSz != PUF_ACTIVATION_CODE_SIZE)
        return BAD_FUNC_ARG;
    if ((ctx.flags & NXP_HWPUF_FLAG_INITED) == 0)
        return HWPUF_INIT_E;
    if ((ctx.flags & NXP_HWPUF_FLAG_ENROLLED) != 0)
        return HWPUF_ENROLL_E;
    if ((ctx.flags & NXP_HWPUF_FLAG_READY) != 0)
        return HWPUF_ENROLL_E;

    ret = PUF_Enroll(PUF, actCode, actCodeSz);
    if (ret == kStatus_EnrollNotAllowed) {
        /* power cycle and try again */
        (void)PUF_PowerCycle(PUF, &conf);
        ret = PUF_Enroll(PUF, actCode, actCodeSz);
    }
    if (ret != kStatus_Success) {
        return HWPUF_ENROLL_E;
    }

    ctx.flags |= NXP_HWPUF_FLAG_ENROLLED;

    return 0;
}

WOLFSSL_API int nxp_hwpuf_Start(byte* actCode, word32 actCodeSz)
{
    int ret;

    WOLFSSL_ENTER("nxp_hwpuf_Start");

    if (actCode == NULL || actCodeSz != PUF_ACTIVATION_CODE_SIZE)
        return BAD_FUNC_ARG;
    if ((ctx.flags & NXP_HWPUF_FLAG_INITED) == 0)
        return HWPUF_INIT_E;
    if ((ctx.flags & NXP_HWPUF_FLAG_ENROLLED) != 0)
        return HWPUF_START_E;
    if ((ctx.flags & NXP_HWPUF_FLAG_READY) != 0)
        return HWPUF_START_E;

    ret = PUF_Start(PUF, actCode, actCodeSz);
    if (ret == kStatus_StartNotAllowed) {
        /* power cycle and try again */
        (void)PUF_PowerCycle(PUF, &conf);
        ret = PUF_Start(PUF, actCode, actCodeSz);
    }
    if (ret != kStatus_Success) {
        return HWPUF_START_E;
    }

    ctx.flags |= NXP_HWPUF_FLAG_READY;

    return 0;
}

WOLFSSL_API int nxp_hwpuf_GenerateKey(byte keyIdx, word32 keySz,
                                 byte* keyCode, word32 keyCodeSz)
{
    int ret;
    word32 kcSz;

    WOLFSSL_ENTER("nxp_hwpuf_GenerateKey");

    if ((ctx.flags & NXP_HWPUF_FLAG_READY) == 0)
        return HWPUF_START_E;
    /* keyidx 0 keys are only delivered over the hw bus, not supported */
    if (keyIdx == kPUF_KeyIndex_00 || keyIdx > kPUF_KeyIndexMax)
        return BAD_FUNC_ARG;
    if ( !HWPUF_KEY_SIZE_IS_VALID(keySz) )
        return BAD_FUNC_ARG;
    kcSz = PUF_GET_KEY_CODE_SIZE_FOR_KEY_SIZE(keySz);
    if (keyCode == NULL || kcSz != keyCodeSz)
        return BAD_FUNC_ARG;

    ret = PUF_SetIntrinsicKey(PUF, (puf_key_index_register_t)keyIdx, keySz,
                              keyCode, keyCodeSz);
    if (ret != kStatus_Success)
        return HWPUF_GENERATE_KEY_E;

    return 0;
}

WOLFSSL_API int nxp_hwpuf_GetKey(byte* keyCode, word32 keyCodeSz,
                            byte* key, word32 keySz)
{
    int ret;
    word32 keyidx, keysize;

    WOLFSSL_ENTER("nxp_hwpuf_GetKey");

    ret = keyCodeParse(keyCode, keyCodeSz, &keyidx, &keysize);
    if (ret != 0)
        return ret;
    /* keyidx 0 keys are only delivered over the hw bus, not supported */
    if (keyidx == kPUF_KeyIndex_00 || key == NULL || keysize != keySz)
        return BAD_FUNC_ARG;

    ret = PUF_GetKey(PUF, keyCode, keyCodeSz, key, keySz);
    if (ret != kStatus_Success) {
        ForceZero(key, keySz);
        return HWPUF_GET_KEY_E;
    }
    return 0;
}

WOLFSSL_API int nxp_hwpuf_Zeroize(void)
{
    int ret;

    WOLFSSL_ENTER("nxp_hwpuf_Zeroize");

    ForceZero(&ctx, sizeof(ctx));

    ret = PUF_Zeroize(PUF);
    PUF_Deinit(PUF, &conf);
    if (ret != kStatus_Success) {
        return HWPUF_ZEROIZE_E;
    }
    return 0;
}

#endif /* WOLFSSL_NXP_HWPUF */
