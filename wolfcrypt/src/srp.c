/* srp.c
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFCRYPT_HAVE_SRP

#include <wolfssl/wolfcrypt/srp.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

static int SrpHashInit(Srp* srp)
{
    switch (srp->type) {
    #ifndef NO_SHA
        case SRP_TYPE_SHA:
            return wc_InitSha(&srp->hash.sha);
    #endif

    #ifndef NO_SHA256
        case SRP_TYPE_SHA256:
            return wc_InitSha256(&srp->hash.sha256);
    #endif

    #ifdef WOLFSSL_SHA384
        case SRP_TYPE_SHA384:
            return wc_InitSha384(&srp->hash.sha384);
    #endif

    #ifdef WOLFSSL_SHA512
        case SRP_TYPE_SHA512:
            return wc_InitSha512(&srp->hash.sha512);
    #endif

        default: return BAD_FUNC_ARG;
    }
}

static int SrpHashUpdate(Srp* srp, byte* data, word32 size)
{
    switch (srp->type) {
    #ifndef NO_SHA
        case SRP_TYPE_SHA:
            return wc_ShaUpdate(&srp->hash.sha, data, size);
    #endif

    #ifndef NO_SHA256
        case SRP_TYPE_SHA256:
            return wc_Sha256Update(&srp->hash.sha256, data, size);
    #endif

    #ifdef WOLFSSL_SHA384
        case SRP_TYPE_SHA384:
            return wc_Sha384Update(&srp->hash.sha384, data, size);
    #endif

    #ifdef WOLFSSL_SHA512
        case SRP_TYPE_SHA512:
            return wc_Sha512Update(&srp->hash.sha512, data, size);
    #endif

        default: return BAD_FUNC_ARG;
    }
}

static int SrpHashFinal(Srp* srp, byte* digest)
{
    switch (srp->type) {
    #ifndef NO_SHA
        case SRP_TYPE_SHA:
            return wc_ShaFinal(&srp->hash.sha, digest);
    #endif

    #ifndef NO_SHA256
        case SRP_TYPE_SHA256: return
            wc_Sha256Final(&srp->hash.sha256, digest);
    #endif

    #ifdef WOLFSSL_SHA384
        case SRP_TYPE_SHA384: return
            wc_Sha384Final(&srp->hash.sha384, digest);
    #endif

    #ifdef WOLFSSL_SHA512
        case SRP_TYPE_SHA512: return
            wc_Sha512Final(&srp->hash.sha512, digest);
    #endif

        default: return BAD_FUNC_ARG;
    }
}

int wc_SrpInit(Srp* srp, byte type, byte side, byte* N, word32 nSz,
                                                            byte* g, word32 gSz)
{
    int ret = 0;

    if (!srp || !N || !g)
        return BAD_FUNC_ARG;

    if (side != SRP_CLIENT_SIDE && side != SRP_SERVER_SIDE)
        return BAD_FUNC_ARG;

    srp->side = side;
    srp->type = type; /* a valid type is checked inside SrpHashXXX functions. */

    if (mp_init_multi(&srp->N, &srp->g, &srp->s, 0, 0, 0) != MP_OKAY)
        return MP_INIT_E;

    if (mp_read_unsigned_bin(&srp->N, N, nSz) != MP_OKAY)
        ret = MP_READ_E;

    if (ret == 0 && mp_read_unsigned_bin(&srp->g, g, gSz) != MP_OKAY)
        ret = MP_READ_E;

    if (ret == 0) ret = SrpHashInit(srp);
    if (ret == 0) ret = SrpHashUpdate(srp, N, nSz);
    if (ret == 0) ret = SrpHashUpdate(srp, g, gSz);
    if (ret == 0) ret = SrpHashFinal(srp, srp->k);

    if (ret != 0) {
        mp_clear(&srp->N); mp_clear(&srp->g); mp_clear(&srp->s);
    }

    return ret;
}

#endif /* WOLFCRYPT_HAVE_SRP */
